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

// [V1: FIX] - Restrict member directory listing to admin and coach roles only.
// Regular members are strictly disallowed from listing all registered club members,
// preventing unrestricted horizontal and vertical data exposure across accounts (OWASP A01:2021).
router.get("/", authorize("admin", "coach"), getAllMembers);
router.get("/attendance/today", authorize("admin", "coach"), getDailyAttendance);

// [V1: FIX] - Enforce defense-in-depth route-level authentication and role validation.
// Access to member profile records by ID is restricted to authorized roles (admin, coach, member);
// individual ownership (req.user.id === member._id) is enforced in the controller.
router.get("/:id", authorize("admin", "coach", "member"), getMemberById);
router.put("/:id", authorize("admin"), validate(updateMemberSchema), updateMember);
router.patch("/:id/status", authorize("admin"), toggleMemberStatus);

// [V1: FIX] - Enforce defense-in-depth route-level authorization on attendance history.
// Lookups are guarded so that members may only retrieve their own attendance records,
// while coaches can only query members in their assigned sport (OWASP A01:2021 IDOR fix).
router.get("/:id/attendance", authorize("admin", "coach", "member"), getAttendance);
router.post("/:id/attendance", authorize("admin", "coach"), validate(attendanceSchema), logAttendance);

export default router;
