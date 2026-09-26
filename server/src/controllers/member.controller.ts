import { Request, Response } from "express";
import mongoose from "mongoose";
import User from "../models/User";
import Session from "../models/Session";
import { AuthRequest } from "../middleware/auth";

export const getAllMembers = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    // [SECURITY][V6] VULNERABLE: NoSQL injection - req.query values are used in the Mongo filter without type checking (e.g. ?status[$ne]=x). OWASP A03:2021
    const { search, role, status, sport, page = "1", limit = "20" } = req.query;

    const query: any = {};
    if (search) {
      query.$or = [
        { name: { $regex: search, $options: "i" } },
        { email: { $regex: search, $options: "i" } },
      ];
    }
    if (role) query.role = role;
    if (status) query.status = status;
    if (sport) query.sport = sport;

    if (req.user?.role === "coach") {
      const coach = await User.findById(req.user.id).select("sport");
      if (!coach) {
        res.status(404).json({ message: "Coach not found" });
        return;
      }
      query.role = "member";
      if (coach.sport) query.sport = coach.sport;
    }

    const pageNum = Number.parseInt(page as string, 10);
    const limitNum = Number.parseInt(limit as string, 10);
    const skip = (pageNum - 1) * limitNum;

    const [members, total] = await Promise.all([
            // [SECURITY][V6] VULNERABLE: unsanitized query object is passed directly to User.find() and User.countDocuments(). OWASP A03:2021
      User.find(query).select("-password").skip(skip).limit(limitNum).sort({ createdAt: -1 }),
      User.countDocuments(query),
    ]);

    res.json({
      members,
      pagination: {
        current: pageNum,
        pages: Math.ceil(total / limitNum),
        total,
      },
    });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to fetch members", error: error.message });
  }
};

export const getMemberById = async (req: Request, res: Response): Promise<void> => {
  try {
    const authReq = req as AuthRequest;
    const member = await User.findById(req.params.id).select("-password");
    if (!member) {
      res.status(404).json({ message: "Member not found" });
      return;
    }

    if (authReq.user?.role === "member" && authReq.user.id !== member._id.toString()) {
      res.status(403).json({ message: "Access denied." });
      return;
    }

    if (authReq.user?.role === "coach") {
      const coach = await User.findById(authReq.user.id).select("sport");
      if (!coach) {
        res.status(404).json({ message: "Coach not found" });
        return;
      }
      if (member.role !== "member" || member.sport !== coach.sport) {
        res.status(403).json({ message: "Coaches can only view members in their sport." });
        return;
      }
    }

    res.json(member);
  } catch (error: any) {
    res.status(500).json({ message: "Failed to fetch member", error: error.message });
  }
};

export const updateMember = async (req: Request, res: Response): Promise<void> => {
  try {
    const allowedKeys = new Set(["status", "assignedCoachId"]);
    const updateKeys = Object.keys(req.body || {});
    const hasInvalidKey = updateKeys.some((key) => !allowedKeys.has(key));
    if (hasInvalidKey) {
      res.status(403).json({
        message: "Admins can only manage active/inactive status and assigned coach from member management.",
      });
      return;
    }

    const updatePayload: any = { ...req.body };
    if (typeof updatePayload.assignedCoachId === "string" && !updatePayload.assignedCoachId.trim()) {
      delete updatePayload.assignedCoachId;
    }

    if (updatePayload.assignedCoachId) {
      const coach = await User.findById(updatePayload.assignedCoachId).select("role sport");
      if (!coach || coach.role !== "coach") {
        res.status(400).json({ message: "Assigned coach is invalid." });
        return;
      }
      // Check if coach sport matches member sport
      const member = await User.findById(req.params.id).select("sport");
      if (member && coach.sport !== member.sport) {
        res.status(400).json({ message: "Assigned coach must match the member sport." });
        return;
      }
    }

    const member = await User.findByIdAndUpdate(
      req.params.id,
      { $set: updatePayload },
      { new: true, runValidators: true }
    ).select("-password");

    if (!member) {
      res.status(404).json({ message: "Member not found" });
      return;
    }

    res.json({ message: "Member updated successfully", member });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to update member", error: error.message });
  }
};

export const toggleMemberStatus = async (req: Request, res: Response): Promise<void> => {
  try {
    const member = await User.findById(req.params.id);
    if (!member) {
      res.status(404).json({ message: "Member not found" });
      return;
    }

    member.status = member.status === "active" ? "inactive" : "active";
    await member.save();

    res.json({
      message: `Member ${member.status === "active" ? "activated" : "deactivated"} successfully`,
      status: member.status,
    });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to update status", error: error.message });
  }
};

export const getAttendance = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const member = await User.findById(req.params.id)
      .select("attendance name sport role")
      .populate("attendance.sessionId", "eventName date location");

    if (!member) {
      res.status(404).json({ message: "Member not found" });
      return;
    }

    if (req.user?.role === "member" && req.user.id !== member._id.toString()) {
      res.status(403).json({ message: "Members can only view their own attendance." });
      return;
    }

    if (req.user?.role === "coach") {
      const coach = await User.findById(req.user.id).select("sport");
      if (!coach) {
        res.status(404).json({ message: "Coach not found" });
        return;
      }
      if (member.role !== "member" || member.sport !== coach.sport) {
        res.status(403).json({ message: "Coaches can only view attendance of members in their sport." });
        return;
      }
    }

    res.json({ name: member.name, attendance: member.attendance });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to fetch attendance", error: error.message });
  }
};

export const getDailyAttendance = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
        // [SECURITY][V6] VULNERABLE: "date" from req.query is not type-checked (can be an object/array instead of a string). OWASP A03:2021
    const { date } = req.query;
    const targetDate = date ? new Date(date as string) : new Date();
    const startOfDay = new Date(targetDate);
    startOfDay.setHours(0, 0, 0, 0);
    const endOfDay = new Date(targetDate);
    endOfDay.setHours(23, 59, 59, 999);

    const query: any = { role: "member" };
    if (req.user?.role === "coach") {
      const coach = await User.findById(req.user.id).select("sport");
      if (!coach) {
        res.status(404).json({ message: "Coach not found" });
        return;
      }
      query.sport = coach.sport;
    }

    const members = await User.find(query).select("name sport attendance");

    const attendanceRecords = members.flatMap((member) =>
      member.attendance
        .filter((att) => {
          const attDate = new Date(att.date);
          return attDate >= startOfDay && attDate <= endOfDay;
        })
        .map((att) => ({
          memberId: member._id,
          memberName: member.name,
          sport: member.sport,
          date: att.date,
        }))
    );

    res.json({ attendance: attendanceRecords });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to fetch daily attendance", error: error.message });
  }
};

export const logAttendance = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const { date, sessionId, note } = req.body;
    const member = await User.findById(req.params.id);

    if (!member) {
      res.status(404).json({ message: "Member not found" });
      return;
    }

    if (req.user?.role === "coach") {
      if (member.role !== "member") {
        res.status(403).json({ message: "Coaches can only mark attendance for members." });
        return;
      }
      const coach = await User.findById(req.user.id).select("sport");
      if (!coach) {
        res.status(404).json({ message: "Coach not found" });
        return;
      }

      if (member.sport !== coach.sport) {
        res.status(403).json({
          message: "Coaches can only log attendance for members in their sport.",
        });
        return;
      }
    }

    if (req.user?.role === "admin" && member.role === "member" && sessionId) {
      const relatedSession = await Session.findById(sessionId).select("_id");
      if (!relatedSession) {
        res.status(400).json({ message: "Session does not exist." });
        return;
      }
    }

    if (req.user?.role === "admin" && member.role === "coach" && member.createdByAdminId) {
      const creatorId = member.createdByAdminId.toString();
      if (creatorId && creatorId !== req.user.id) {
        // Relationship is still preserved, but all admins remain authorized.
      }
    }

    if (req.user?.role !== "admin" && member.role === "coach") {
      res.status(403).json({ message: "Only admins can mark attendance for coaches." });
      return;
    }

    const attendanceDate = date ? new Date(date) : new Date();

    // Check if attendance already marked for this date
    const existingAttendance = member.attendance.find(att => {
      const attDate = new Date(att.date);
      return attDate.toDateString() === attendanceDate.toDateString();
    });

    if (existingAttendance) {
      res.status(400).json({ message: "Attendance already marked for this date." });
      return;
    }

    member.attendance.push({
      date: attendanceDate,
      sessionId,
      markedBy: req.user?.id ? new mongoose.Types.ObjectId(req.user.id) : undefined,
      note,
    });

    await member.save();
    res.json({ message: "Attendance logged successfully" });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to log attendance", error: error.message });
  }
};

export const getDashboardStats = async (_req: Request, res: Response): Promise<void> => {
  try {
    const [totalMembers, activeMembers, coaches, sportCounts] = await Promise.all([
      User.countDocuments({ role: "member" }),
      User.countDocuments({ role: "member", status: "active" }),
      User.countDocuments({ role: "coach" }),
      User.aggregate([
        { $match: { role: "member" } },
        { $group: { _id: "$sport", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
      ]),
    ]);

    res.json({
      totalMembers,
      activeMembers,
      inactiveMembers: totalMembers - activeMembers,
      coaches,
      sportBreakdown: sportCounts,
    });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to fetch stats", error: error.message });
  }
};
