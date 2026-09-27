import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import User from "../models/User";
import { getJwtSecret } from "../config/jwt";

export interface AuthRequest extends Request {
  user?: {
    id: string;
    role: string;
    email: string;
  };
}

export const authenticate = async (
  req: AuthRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      res.status(401).json({ message: "Access denied. No token provided." });
      return;
    }

    const token = authHeader.split(" ")[1];
    // [V2: FIX] (OWASP A02:2021 - Cryptographic Failures):
    // Cryptographic secret retrieved via getJwtSecret() which enforces strict validation
    // and throws immediately if JWT_SECRET is missing or matches known weak fallback keys.
    const secret = getJwtSecret();
    const decoded = jwt.verify(token, secret) as {
      id: string;
      role: string;
      email: string;
    };

    // SECURITY FIX (V4): Added active-status validation to ensure deactivated accounts
    // cannot access protected API routes, even if their token hasn't expired yet.
    const user = await User.findById(decoded.id);
    if (!user || user.status !== "active") {
      res.status(401).json({ message: "Session invalid. Account is deactivated." });
      return;
    }

    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid or expired token." });
  }
};

export const authenticateOptional = async (
  req: AuthRequest,
  _res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      next();
      return;
    }

    const token = authHeader.split(" ")[1];
    // [V2: FIX] (OWASP A02:2021 - Cryptographic Failures):
    // Use getJwtSecret() to enforce valid signing key for optional authentication.
    const secret = getJwtSecret();
    const decoded = jwt.verify(token, secret) as {
      id: string;
      role: string;
      email: string;
    };

    // SECURITY FIX (V4): Ensure we do not implicitly authenticate an inactive account.
    const user = await User.findById(decoded.id);
    if (user && user.status === "active") {
      req.user = decoded;
    }
    
    next();
  } catch {
    next();
  }
};
