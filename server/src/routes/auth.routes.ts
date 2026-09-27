import { Router } from "express";
import {
	register,
	login,
	refreshToken,
	getMe,
	updateMe,
	changeMyPassword,
	deleteMyAccount,
	googleLogin,
} from "../controllers/auth.controller";
import { authenticate, authenticateOptional } from "../middleware/auth";
import { validate } from "../middleware/validate";
import {
	registerSchema,
	loginSchema,
	updateMeSchema,
	changePasswordSchema,
	deleteMyAccountSchema,
} from "../validators/auth.validator";

const router = Router();

router.post("/register", authenticateOptional, validate(registerSchema), register);
router.post("/login", validate(loginSchema), login);
router.post("/google-login", googleLogin);
router.post("/refresh", refreshToken);
router.get("/me", authenticate, getMe);
router.put("/me", authenticate, validate(updateMeSchema), updateMe);
router.put("/me/password", authenticate, validate(changePasswordSchema), changeMyPassword);
router.delete("/me", authenticate, validate(deleteMyAccountSchema), deleteMyAccount);

export default router;
