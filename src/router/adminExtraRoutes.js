// src/router/adminExtraRoutes.js
import { Router } from "express";
import {
	verifyEmail,
	resendVerificationEmail,
	forgotPassword,
	resetPassword,
	sendTwoFactorOTP,
	verifyTwoFactorOTP,
	sendLoginOTP,
	verifyLoginOTP,
} from "../controllers/adminExtraController.js";
import { protect } from "../middlewares/authMiddleware.js";

export default function adminExtraRoutes(version) {
	const router = Router();

	// Public endpoints for extra functionalities
	router.get(`/api/v${version}/admin/verify-email`, verifyEmail);
	router.post(
		`/api/v${version}/admin/resend-verification`,
		resendVerificationEmail
	);
	router.post(`/api/v${version}/admin/forgot-password`, forgotPassword);
	router.post(`/api/v${version}/admin/reset-password`, resetPassword);
	router.post(`/api/v${version}/admin/send-twofactor-otp`, sendTwoFactorOTP);
	router.post(
		`/api/v${version}/admin/verify-twofactor-otp`,
		verifyTwoFactorOTP
	);
	router.post(`/api/v${version}/admin/send-login-otp`, sendLoginOTP);
	router.post(`/api/v${version}/admin/verify-login-otp`, verifyLoginOTP);

	// Protected endpoints (if needed) can be added here
	// e.g., router.use(protect);

	return router;
}
