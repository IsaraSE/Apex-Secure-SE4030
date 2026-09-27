import { Request, Response } from "express";
import Session from "../models/Session";
import User from "../models/User";
import { AuthRequest } from "../middleware/auth";
import { notifyMembersBySport } from "../services/notification.service";
import { toSafeString, toSafeObjectId } from "../utils/sanitize";

const toSessionDateTime = (date: Date | string, time: string): Date => {
  const day = new Date(date).toISOString().split("T")[0];
  return new Date(`${day}T${time}:00`);
};

const isPastSessionStart = (date: Date | string, startTime: string): boolean =>
  toSessionDateTime(date, startTime).getTime() < Date.now();

export const autoCompleteOverdueSessions = async (): Promise<number> => {
  const now = new Date();
  const scheduledSessions = await Session.find({ status: "scheduled", date: { $lte: now } }).select(
    "_id date endTime"
  );

  const overdueIds = scheduledSessions
    .filter((session) => toSessionDateTime(session.date, session.endTime).getTime() < now.getTime())
    .map((session) => session._id);

  if (!overdueIds.length) {
    return 0;
  }

  const result = await Session.updateMany(
    { _id: { $in: overdueIds } },
    { $set: { status: "completed" } }
  );

  return result.modifiedCount;
};

const checkConflict = async (
  coachId: string,
  date: string,
  startTime: string,
  endTime: string,
  excludeId?: string
) => {
  const query: any = {
    coachId,
    date: new Date(date),
    status: { $ne: "cancelled" },
    $or: [
      { startTime: { $lt: endTime }, endTime: { $gt: startTime } },
    ],
  };

  if (excludeId) {
    query._id = { $ne: excludeId };
  }

  return Session.findOne(query);
};

export const getAllSessions = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    await autoCompleteOverdueSessions();


    // [SECURITY][V6] VULNERABLE: NoSQL injection - req.query values (sport, status, coachId, dates) are used in the Mongo filter without type checking (e.g. ?status[$ne]=x). OWASP A03:2021
    const search = toSafeString(req.query.search);
    const sport = toSafeString(req.query.sport);
    const status = toSafeString(req.query.status);
    const coachId = toSafeObjectId(req.query.coachId);
    const startDate = toSafeString(req.query.startDate);
    const endDate = toSafeString(req.query.endDate);
    const query: any = {};
    if (search) {
      query.$or = [
        { eventName: { $regex: search, $options: "i" } },
        { location: { $regex: search, $options: "i" } },
      ];
    }
    if (sport) query.sport = sport;
    if (status) query.status = status;
    if (coachId) query.coachId = coachId;

    if (req.user?.role === "coach") {
      query.coachId = req.user.id;
    }

    if (req.user?.role === "member") {
      const member = await User.findById(req.user.id).select("sport");
      if (!member) {
        res.status(404).json({ message: "Member not found" });
        return;
      }
      query.sport = member.sport;
    }

    if (startDate || endDate) {
      query.date = {};
      if (startDate) query.date.$gte = new Date(startDate as string);
      if (endDate) query.date.$lte = new Date(endDate as string);
    }


    // [SECURITY][V6] VULNERABLE: unsanitized query object is passed directly to Session.find(). OWASP A03:2021
    const sessions = await Session.find(query)
      .populate("coachId", "name email sport")
      .sort({ date: 1, startTime: 1 });

    res.json(sessions);
  } catch (error: any) {
    res.status(500).json({ message: "Failed to fetch sessions", error: error.message });
  }
};

export const createSession = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const payload = { ...req.body };

    if (req.user?.role === "coach") {
      payload.coachId = req.user.id;
      const coach = await User.findById(req.user.id).select("sport");
      if (!coach) {
        res.status(404).json({ message: "Coach not found" });
        return;
      }
      payload.sport = coach.sport;
    }

    const { coachId, date, startTime, endTime } = payload;

    if (isPastSessionStart(date, startTime)) {
      res.status(400).json({ message: "Cannot create sessions in the past." });
      return;
    }

    const assignedCoach = await User.findById(coachId).select("role sport name");
    if (!assignedCoach || assignedCoach.role !== "coach") {
      res.status(400).json({ message: "Assigned coach is invalid." });
      return;
    }

    if (assignedCoach.sport !== payload.sport) {
      res.status(400).json({ message: "Coach sport must match the session sport." });
      return;
    }

    const conflict = await checkConflict(coachId, date, startTime, endTime);
    if (conflict) {
      res.status(409).json({
        message: "Schedule conflict detected",
        conflict: {
          eventName: conflict.eventName,
          date: conflict.date,
          startTime: conflict.startTime,
          endTime: conflict.endTime,
          location: conflict.location,
        },
      });
      return;
    }

    const session = await Session.create(payload);
    const populated = await session.populate("coachId", "name email sport");

    await notifyMembersBySport(payload.sport, {
      type: "session_created",
      title: "New Session Scheduled",
      message: `${payload.eventName} has been scheduled on ${new Date(payload.date).toDateString()} at ${payload.startTime}.`,
      metadata: {
        sessionId: String(session._id),
        eventName: payload.eventName,
        location: payload.location,
      },
    });

    res.status(201).json({ message: "Session created successfully", session: populated });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to create session", error: error.message });
  }
};

export const updateSession = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    const payload = { ...req.body };
    const sessionId = String(req.params.id);

    const existing = await Session.findById(sessionId).select(
      "coachId date startTime endTime location sport eventName"
    );
    if (!existing) {
      res.status(404).json({ message: "Session not found" });
      return;
    }

    if (req.user?.role === "coach" && existing.coachId.toString() !== req.user.id) {
      res.status(403).json({ message: "Coaches can only manage their own sessions." });
      return;
    }

    if (req.user?.role === "coach") {
      payload.coachId = req.user.id;
      const coach = await User.findById(req.user.id).select("sport");
      if (!coach) {
        res.status(404).json({ message: "Coach not found" });
        return;
      }
      payload.sport = coach.sport;
    }

    const nextCoachId = payload.coachId || existing.coachId.toString();
    const nextDate = payload.date || existing.date;
    const nextStartTime = payload.startTime || existing.startTime;
    const nextEndTime = payload.endTime || existing.endTime;

    if (isPastSessionStart(nextDate, nextStartTime)) {
      res.status(400).json({ message: "Cannot schedule sessions in the past." });
      return;
    }

    const assignedCoach = await User.findById(nextCoachId).select("role sport");
    if (!assignedCoach || assignedCoach.role !== "coach") {
      res.status(400).json({ message: "Assigned coach is invalid." });
      return;
    }

    const nextSport = payload.sport || existing.sport;
    if (assignedCoach.sport !== nextSport) {
      res.status(400).json({ message: "Coach sport must match the session sport." });
      return;
    }

    if (nextCoachId && nextDate && nextStartTime && nextEndTime) {
      const conflict = await checkConflict(nextCoachId, String(nextDate), nextStartTime, nextEndTime, sessionId);
      if (conflict) {
        res.status(409).json({
          message: "Schedule conflict detected",
          conflict: {
            eventName: conflict.eventName,
            date: conflict.date,
            startTime: conflict.startTime,
            endTime: conflict.endTime,
          },
        });
        return;
      }
    }

    const isRescheduled =
      (payload.startTime && payload.startTime !== existing.startTime) ||
      (payload.endTime && payload.endTime !== existing.endTime) ||
      (payload.location && payload.location !== existing.location);

    const session = await Session.findByIdAndUpdate(
      sessionId,
      { $set: payload },
      { new: true, runValidators: true }
    ).populate("coachId", "name email sport");

    if (!session) {
      res.status(404).json({ message: "Session not found" });
      return;
    }

    if (isRescheduled) {
      await notifyMembersBySport(session.sport, {
        type: "session_rescheduled",
        title: "Session Rescheduled",
        message: `${session.eventName} has updated time/location details. Please review your schedule.`,
        metadata: {
          sessionId: String(session._id),
          location: session.location,
          startTime: session.startTime,
          endTime: session.endTime,
        },
      });
    }

    res.json({ message: "Session updated successfully", session });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to update session", error: error.message });
  }
};

export const deleteSession = async (req: Request, res: Response): Promise<void> => {
  try {
    const session = await Session.findByIdAndDelete(req.params.id);
    if (!session) {
      res.status(404).json({ message: "Session not found" });
      return;
    }

    await notifyMembersBySport(session.sport, {
      type: "session_deleted",
      title: "Session Deleted",
      message: `${session.eventName} has been deleted from the schedule.`,
      metadata: {
        sessionId: String(session._id),
        eventName: session.eventName,
      },
    });

    res.json({ message: "Session deleted successfully" });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to delete session", error: error.message });
  }
};

export const cancelSession = async (req: AuthRequest, res: Response): Promise<void> => {
  try {
    if (req.user?.role === "coach") {
      const existing = await Session.findById(req.params.id).select("coachId");
      if (!existing) {
        res.status(404).json({ message: "Session not found" });
        return;
      }
      if (existing.coachId.toString() !== req.user.id) {
        res.status(403).json({ message: "Coaches can only manage their own sessions." });
        return;
      }
    }

    const session = await Session.findByIdAndUpdate(
      req.params.id,
      { status: "cancelled" },
      { new: true }
    );

    if (!session) {
      res.status(404).json({ message: "Session not found" });
      return;
    }

    await notifyMembersBySport(session.sport, {
      type: "session_cancelled",
      title: "Session Cancelled",
      message: `${session.eventName} has been cancelled.`,
      metadata: {
        sessionId: String(session._id),
        eventName: session.eventName,
      },
    });

    res.json({ message: "Session cancelled successfully", session });
  } catch (error: any) {
    res.status(500).json({ message: "Failed to cancel session", error: error.message });
  }
};
