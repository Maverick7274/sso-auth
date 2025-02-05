// src/router/userRoutes.js
import { Router } from "express";
import {
	registerUser,
	loginUser,
	validateUserToken,
	logoutUser,
	getUserProfile,
	updateUserProfile,
	deleteUserAccount,
} from "../controllers/userController.js";
import {
	verifyEmail,
	resendVerificationEmail,
	forgotPassword,
	resetPassword,
	sendLoginOTP,
	verifyLoginOTP,
} from "../controllers/userExtraController.js";
import { loginLimiter } from "../middlewares/rateLimiter.js";
import { protect } from "../middlewares/authMiddleware.js";
import { restrictTo } from "../middlewares/restrictTo.js"; // if you need role-based access

export default function userRoutes(version) {
	const router = Router();

	// Public routes
	router.post(`/api/v${version}/auth/register`, registerUser);
	router.post(`/api/v${version}/auth/login`, loginLimiter, loginUser);
	router.get(`/api/v${version}/auth/validate-token`, validateUserToken);
	router.post(`/api/v${version}/auth/forgot-password`, forgotPassword);
	router.post(`/api/v${version}/auth/reset-password`, resetPassword);
	router.get(`/api/v${version}/auth/verify-email`, verifyEmail);
	router.post(
		`/api/v${version}/auth/resend-verification`,
		resendVerificationEmail
	);
	router.post(`/api/v${version}/auth/send-login-otp`, sendLoginOTP);
	router.post(`/api/v${version}/auth/verify-login-otp`, verifyLoginOTP);

	// Protected routes for logged-in users
	router.use(protect);
	router.post(`/api/v${version}/auth/logout`, logoutUser);
	router.get(`/api/v${version}/auth/profile`, getUserProfile);
	router.put(`/api/v${version}/auth/update-profile`, updateUserProfile);
	router.delete(`/api/v${version}/auth/delete-account`, deleteUserAccount);

	return router;
}
