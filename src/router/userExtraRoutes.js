// src/routes/userExtraRoutes.js

import { Router } from "express";
import {
	verifyEmail,
	resendVerificationEmail,
	forgotPassword,
	resetPassword,
	sendTwoFactorOTP,
	verifyTwoFactorOTP,
	getVerificationStatus,
	enableTwoFactorAuth,
	disableTwoFactorAuth,
	oidcAuthorizeUser,
	oidcTokenUser,
	oidcUserUserInfo,
} from "../controllers/userExtraController.js";
import { userProtect } from "../middlewares/authMiddleware.js";

export default function userExtraRoutes(version) {
	const router = Router();

	// Email verification endpoints
	router.get(`/api/v${version}/user/verify-email`, verifyEmail);
	router.post(
		`/api/v${version}/user/resend-verification`,
		resendVerificationEmail
	);

	// Verification status endpoint
	router.get(
		`/api/v${version}/user/verification-status`,
		userProtect,
		getVerificationStatus
	);

	// Password reset endpoints
	router.post(`/api/v${version}/user/forgot-password`, forgotPassword);
	router.post(`/api/v${version}/user/reset-password`, resetPassword);

	// Two-factor authentication endpoints
	router.post(`/api/v${version}/user/send-otp`, sendTwoFactorOTP);
	router.post(`/api/v${version}/user/verify-otp`, verifyTwoFactorOTP);

	// Endpoints to enable/disable two-factor auth
	router.post(
		`/api/v${version}/user/enable-two-factor`,
		userProtect,
		enableTwoFactorAuth
	);
	router.post(
		`/api/v${version}/user/disable-two-factor`,
		userProtect,
		disableTwoFactorAuth
	);

	// ---------- New OIDC Endpoints for Users ----------
	router.get(
		`/api/v${version}/oidc/user/authorize`,
		userProtect,
		oidcAuthorizeUser
	);
	router.post(`/api/v${version}/oidc/user/token`, userProtect, oidcTokenUser);
	router.get(
		`/api/v${version}/oidc/user/userinfo`,
		userProtect,
		oidcUserUserInfo
	);

	return router;
}
