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

	// Email Verification Routes
	// GET: /api/v{version}/user/verify-email
	// Verifies the user's email address.
	router.get(`/api/v${version}/user/verify-email`, verifyEmail);

	// POST: /api/v{version}/user/resend-verification
	// Resends the verification email if the user did not receive it.
	router.post(
		`/api/v${version}/user/resend-verification`,
		resendVerificationEmail
	);

	// Verification Status Route
	// GET: /api/v{version}/user/verification-status
	// Returns the user's email verification status (protected).
	router.get(
		`/api/v${version}/user/verification-status`,
		userProtect,
		getVerificationStatus
	);

	// Password Reset Routes
	// POST: /api/v{version}/user/forgot-password
	// Initiates the forgot password process.
	router.post(`/api/v${version}/user/forgot-password`, forgotPassword);

	// POST: /api/v{version}/user/reset-password
	// Resets the password using a valid token.
	router.post(`/api/v${version}/user/reset-password`, resetPassword);

	// Two-Factor Authentication Routes
	// POST: /api/v{version}/user/send-otp
	// Sends an OTP for two-factor authentication.
	router.post(`/api/v${version}/user/send-otp`, sendTwoFactorOTP);

	// POST: /api/v${version}/user/verify-otp
	// Verifies the OTP entered by the user.
	router.post(`/api/v${version}/user/verify-otp`, verifyTwoFactorOTP);

	// Two-Factor Enable/Disable Routes (Protected)
	// POST: /api/v{version}/user/enable-two-factor
	// Enables two-factor authentication.
	router.post(
		`/api/v${version}/user/enable-two-factor`,
		userProtect,
		enableTwoFactorAuth
	);

	// POST: /api/v{version}/user/disable-two-factor
	// Disables two-factor authentication.
	router.post(
		`/api/v${version}/user/disable-two-factor`,
		userProtect,
		disableTwoFactorAuth
	);

	// OpenID Connect (OIDC) Routes for Users (Protected)
	// GET: /api/v{version}/oidc/user/authorize
	// Authorizes the user for OIDC.
	router.get(
		`/api/v${version}/oidc/user/authorize`,
		userProtect,
		oidcAuthorizeUser
	);

	// POST: /api/v{version}/oidc/user/token
	// Issues an OIDC token after successful user authentication.
	router.post(`/api/v${version}/oidc/user/token`, userProtect, oidcTokenUser);

	// GET: /api/v{version}/oidc/user/userinfo
	// Retrieves user information based on the provided OIDC token.
	router.get(
		`/api/v${version}/oidc/user/userinfo`,
		userProtect,
		oidcUserUserInfo
	);

	return router;
}
