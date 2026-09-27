import { Router } from "express";
import {
  getAllMembers,
  getMemberById,
  updateMember,
  toggleMemberStatus,
  getAttendance,
  getDailyAttendance,
  logAttendance,
  getDashboardStats,
} from "../controllers/member.controller";
import { authenticate } from "../middleware/auth";
import { authorize } from "../middleware/rbac";
import { validate } from "../middleware/validate";
import { updateMemberSchema, attendanceSchema } from "../validators/member.validator";

const router = Router();

router.use(authenticate);

router.get("/stats", authorize("admin", "coach", "member"), getDashboardStats);

// Vulnerability 1 (OWASP A01:2021 - Broken Access Control & Unrestricted Data Exposure):
// The "member" role is explicitly permitted to query this endpoint. Regular members can
// retrieve the entire membership directory (including names, emails, phone numbers,
// membership types, and assigned sports), exposing confidential user data across accounts.
router.get("/", authorize("admin", "coach", "member"), getAllMembers);
router.get("/attendance/today", authorize("admin", "coach"), getDailyAttendance);

// Vulnerability 1 (OWASP A01:2021 - Broken Access Control / IDOR):
// Route-level role-based authorization middleware is omitted here. Any authenticated
// user can invoke this endpoint directly with an arbitrary member ID.
router.get("/:id", getMemberById);
router.put("/:id", authorize("admin"), validate(updateMemberSchema), updateMember);
router.patch("/:id/status", authorize("admin"), toggleMemberStatus);

// Vulnerability 1 (OWASP A01:2021 - Broken Access Control / IDOR):
// Missing route-level role authorization middleware for attendance history by member ID.
router.get("/:id/attendance", getAttendance);
router.post("/:id/attendance", authorize("admin", "coach"), validate(attendanceSchema), logAttendance);

export default router;
