// src/router/userExtraRoutes.js
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
} from "../controllers/userExtraController.js";
import { protect } from "../middlewares/authMiddleware.js";

export default function userExtraRoutes(version) {
	const router = Router();

	// Use dynamic version in the paths
	router.get(`/api/v${version}/auth/verify-email`, verifyEmail);
	router.post(
		`/api/v${version}/auth/resend-verification`,
		resendVerificationEmail
	);
	router.post(`/api/v${version}/auth/forgot-password`, forgotPassword);
	router.post(`/api/v${version}/auth/reset-password`, resetPassword);
	router.post(`/api/v${version}/auth/send-twofactor-otp`, sendTwoFactorOTP);
	router.post(
		`/api/v${version}/auth/verify-twofactor-otp`,
		verifyTwoFactorOTP
	);
	router.post(`/api/v${version}/auth/send-login-otp`, sendLoginOTP);
	router.post(`/api/v${version}/auth/verify-login-otp`, verifyLoginOTP);

	// (Add any protected endpoints here if needed)
	return router;
}
