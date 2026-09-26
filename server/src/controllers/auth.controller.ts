import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User";
import { AuthRequest } from "../middleware/auth";
import { logger, logSecurityEvent } from "../utils/logger";

const generateTokens = (user: any) => {
  const payload = { id: user._id, role: user.role, email: user.email };
  const accessExpiresIn = (process.env.JWT_EXPIRES_IN || "1d") as jwt.SignOptions["expiresIn"];
  const refreshExpiresIn = (process.env.JWT_REFRESH_EXPIRES_IN || "7d") as jwt.SignOptions["expiresIn"];

  const accessToken = jwt.sign(
    payload,
    process.env.JWT_SECRET || "fallback_secret",
    { expiresIn: accessExpiresIn }
  );

  const refreshToken = jwt.sign(
    payload,
    process.env.JWT_REFRESH_SECRET || "fallback_refresh_secret",
    { expiresIn: refreshExpiresIn }
  );

  return { accessToken, refreshToken };
};

export const register = async (req: Request, res: Response): Promise<void> => {
  try {
    const authReq = req as AuthRequest;
    const { name, email, password, role, sport, membershipType, phone, assignedCoachId } = req.body;
    const targetRole = role || "member";
    const cleanAssignedCoachId =
      assignedCoachId && String(assignedCoachId).trim() ? String(assignedCoachId).trim() : undefined;

    if (targetRole !== "member") {
      if (authReq.user?.role !== "admin") {
        res.status(403).json({ message: "Only admins can create coach or admin accounts." });
        return;
      }
    }

    const existingUser = await User.findOne({ email: String(email).toLowerCase() });
    if (existingUser) {
      res.status(409).json({ message: "Email already registered" });
      return;
    }

    if (cleanAssignedCoachId && targetRole !== "member") {
      res.status(400).json({ message: "Coach assignment is only valid for members." });
      return;
    }

    if (cleanAssignedCoachId) {
      const assignedCoach = await User.findById(cleanAssignedCoachId).select("role sport");
      if (!assignedCoach || assignedCoach.role !== "coach") {
        res.status(400).json({ message: "Assigned coach is invalid." });
        return;
      }
      if (assignedCoach.sport !== sport) {
        res.status(400).json({ message: "Assigned coach must match the member sport." });
        return;
      }
    }

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = await User.create({
      name,
      email: String(email).toLowerCase(),
      password: hashedPassword,
      role: targetRole,
      sport,
      membershipType: membershipType || "monthly",
      phone,
      assignedCoachId: cleanAssignedCoachId,
      createdByAdminId: targetRole === "coach" && authReq.user?.id ? authReq.user.id : undefined,
    });

    const tokens = generateTokens(user);

    logSecurityEvent("REGISTRATION", req, { email: user.email, role: user.role });

    res.status(201).json({
      message: "Registration successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        sport: user.sport,
        status: user.status,
      },
      ...tokens,
    });
  } catch (error: any) {
    logger.error("Registration failed", { stack: error.stack, method: req.method, path: req.originalUrl, ip: req.ip });
    res.status(500).json({ message: "Registration failed" });
  }
};

export const login = async (req: Request, res: Response): Promise<void> => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      logSecurityEvent("LOGIN_FAILED_UNKNOWN_EMAIL", req, { email });
      res.status(401).json({ message: "Invalid email or password" });
      return;
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      logSecurityEvent("LOGIN_FAILED_BAD_PASSWORD", req, { email, userId: user._id });
      res.status(401).json({ message: "Invalid email or password" });
      return;
    }

    if (user.status === "inactive") {
      logSecurityEvent("LOGIN_FAILED_INACTIVE_ACCOUNT", req, { email, userId: user._id });
      res.status(403).json({ message: "Account is deactivated. Contact admin." });
      return;
    }

    const tokens = generateTokens(user);

    logSecurityEvent("LOGIN_SUCCESS", req, { email, userId: user._id });

    res.json({
      message: "Login successful",
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role,
        sport: user.sport,
        status: user.status,
      },
      ...tokens,
    });
  } catch (error: any) {
    logger.error("Login failed", { stack: error.stack, method: req.method, path: req.originalUrl, ip: req.ip });
    res.status(500).json({ message: "Login failed" });
  }
};

export const refreshToken = async (req: Request, res: Response): Promise<void> => {
  try {
    const { refreshToken } = req.body;
    if (!refreshToken) {
      res.status(400).json({ message: "Refresh token is required" });
      return;
    }

    const decoded = jwt.verify(
      refreshToken,
      process.env.JWT_REFRESH_SECRET || "fallback_refresh_secret"
    ) as any;

    const user = await User.findById(decoded.id);
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    const tokens = generateTokens(user);
    res.json({ ...tokens });
  } catch (error: unknown) {
    logger.warn("Refresh token failed", {
      stack: error instanceof Error ? error.stack : undefined,
      method: req.method,
      path: req.originalUrl,
      ip: req.ip,
    });
    res.status(401).json({ message: "Invalid or expired refresh token" });
  }
};

export const getMe = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const user = await User.findById(req.user?.id).select("-password");
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }
    res.json(user);
  } catch (error: any) {
    logger.error("Failed to fetch profile", { stack: error.stack, method: req.method, path: req.originalUrl, ip: req.ip });
    res.status(500).json({ message: "Failed to fetch profile" });
  }
};

export const updateMe = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "Authentication required." });
      return;
    }

    if (req.user?.role === "admin") {
      res.status(403).json({ message: "Administrators cannot modify their own profile." });
      return;
    }

    const updates: any = {
      name: req.body.name,
      phone: req.body.phone,
      sport: req.body.sport,
      membershipType: req.body.membershipType,
    };

    if (updates.phone) {
      updates.phone = String(updates.phone).trim();
    }

    Object.keys(updates).forEach((key) => {
      if (updates[key] === undefined) delete updates[key];
    });

    // If member is changing sport, check if assigned coach matches new sport
    if (req.user?.role === "member" && updates.sport) {
      const currentUser = await User.findById(userId).select("assignedCoachId sport");
      if (currentUser?.assignedCoachId && currentUser.sport !== updates.sport) {
        const assignedCoach = await User.findById(currentUser.assignedCoachId).select("sport");
        if (assignedCoach && assignedCoach.sport !== updates.sport) {
          updates.assignedCoachId = undefined; // Remove assignment if sport doesn't match
        }
      }
    }

    const user = await User.findByIdAndUpdate(
      userId,
      { $set: updates },
      { new: true, runValidators: true }
    ).select("-password");

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    res.json({ message: "Profile updated successfully", user });
  } catch (error: any) {
    logger.error("Failed to update profile", { stack: error.stack, method: req.method, path: req.originalUrl, ip: req.ip });
    res.status(500).json({ message: "Failed to update profile" });
  }
};

export const changeMyPassword = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "Authentication required." });
      return;
    }

    if (req.user?.role === "admin") {
      res.status(403).json({ message: "Administrators cannot change their own password via this endpoint." });
      return;
    }

    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    const passwordMatches = await bcrypt.compare(currentPassword, user.password);
    if (!passwordMatches) {
      res.status(400).json({ message: "Current password is incorrect." });
      return;
    }

    const samePassword = await bcrypt.compare(newPassword, user.password);
    if (samePassword) {
      res.status(400).json({ message: "New password must be different from current password." });
      return;
    }

    const salt = await bcrypt.genSalt(12);
    user.password = await bcrypt.hash(newPassword, salt);
    await user.save();

    logSecurityEvent("PASSWORD_CHANGED", req, { userId: user._id });

    res.json({ message: "Password changed successfully." });
  } catch (error: any) {
    logger.error("Failed to change password", { stack: error.stack, method: req.method, path: req.originalUrl, ip: req.ip });
    res.status(500).json({ message: "Failed to change password" });
  }
};

export const deleteMyAccount = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const userId = req.user?.id;
    if (!userId) {
      res.status(401).json({ message: "Authentication required." });
      return;
    }

    if (req.user?.role === "admin") {
      res.status(403).json({ message: "Administrators cannot delete their own accounts." });
      return;
    }

    const { currentPassword } = req.body;

    const user = await User.findById(userId);
    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    const passwordMatches = await bcrypt.compare(currentPassword, user.password);
    if (!passwordMatches) {
      res.status(400).json({ message: "Current password is incorrect." });
      return;
    }

    if (user.role === "admin") {
      const activeAdminCount = await User.countDocuments({ role: "admin", status: "active" });
      if (activeAdminCount <= 1) {
        res.status(400).json({ message: "Cannot delete the last active admin account." });
        return;
      }
    }

    await User.findByIdAndDelete(userId);

    logSecurityEvent("ACCOUNT_DELETED", req, { userId });

    res.json({ message: "Account deleted successfully." });
  } catch (error: any) {
    logger.error("Failed to delete account", { stack: error.stack, method: req.method, path: req.originalUrl, ip: req.ip });
    res.status(500).json({ message: "Failed to delete account" });
  }
};
