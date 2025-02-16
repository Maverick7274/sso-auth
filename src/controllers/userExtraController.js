// src/controllers/userExtraController.js

import crypto from "crypto";
import bcrypt from "bcryptjs";
import _ from "lodash";
import User from "../models/User.js";
import { sendResponse } from "../utils/helpers.js";
import {
	sendUserVerificationEmail,
	sendUserResetPasswordEmail,
	sendUserTwoFactorOTPEmail,
} from "../services/emailService.js";

// Use only the Winston logger
import logger from "../utils/logger.js";

// Helper to generate a random token
const generateToken = () => crypto.randomBytes(20).toString("hex");

// ============
// Verify Email
// ============
// GET /api/v1/auth/verify-email?token=XYZ
export const verifyEmail = async (req, res) => {
	try {
		const { token } = req.query;
		if (!token) {
			logger.warn("Verification token missing in request.");
			return sendResponse(res, 400, false, null, "Token is required");
		}

		// Find the user with a matching, unexpired verification token
		const user = await User.findOne({
			emailVerificationToken: token,
			emailVerificationExpires: { $gt: Date.now() },
		});

		if (!user) {
			logger.warn(`Invalid or expired token: ${token}`);
			return sendResponse(
				res,
				400,
				false,
				null,
				"Invalid or expired token"
			);
		}

		user.isVerified = true;
		user.emailVerificationToken = undefined;
		user.emailVerificationExpires = undefined;
		await user.save();

		logger.info(`Email verified for user: ${user._id}`);
		return sendResponse(
			res,
			200,
			true,
			null,
			"Email verified successfully"
		);
	} catch (err) {
		logger.error(`Error in verifyEmail: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v1/auth/resend-verification
export const resendVerificationEmail = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			logger.warn("Resend verification: Email missing in request.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const user = await User.findOne({ email });
		if (!user) {
			logger.warn(
				`Resend verification failed: User not found (${email})`
			);
			return sendResponse(res, 400, false, null, "User not found");
		}
		if (user.isVerified) {
			logger.info(
				`User ${email} already verified; no need to resend email.`
			);
			return sendResponse(
				res,
				400,
				false,
				null,
				"Email already verified"
			);
		}

		// Generate new verification token (expires in 24 hours)
		const token = generateToken();
		user.emailVerificationToken = token;
		user.emailVerificationExpires = Date.now() + 24 * 60 * 60 * 1000;
		await user.save();

		await sendUserVerificationEmail(user.email, token);

		logger.info(`Resent verification email to user: ${user._id}`);
		return sendResponse(res, 200, true, null, "Verification email sent");
	} catch (err) {
		logger.error(`Error in resendVerificationEmail: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ======================
// Forgot Password & Reset
// ======================

// POST /api/v1/auth/forgot-password
export const forgotPassword = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			logger.warn("Forgot password: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const user = await User.findOne({ email });
		if (!user) {
			logger.warn(`Forgot password: User not found for email ${email}`);
			return sendResponse(res, 400, false, null, "User not found");
		}

		// Generate reset token (expires in 1 hour)
		const token = generateToken();
		user.forgotPasswordToken = token;
		user.forgotPasswordExpires = Date.now() + 60 * 60 * 1000;
		await user.save();

		await sendUserResetPasswordEmail(user.email, token);

		logger.info(`Password reset email sent for user: ${user._id}`);
		return sendResponse(res, 200, true, null, "Password reset email sent");
	} catch (err) {
		logger.error(`Error in forgotPassword: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v1/auth/reset-password
export const resetPassword = async (req, res) => {
	try {
		const allowedFields = ["token", "newPassword", "confirmPassword"];
		const data = _.pick(req.body, allowedFields);

		if (!data.token || !data.newPassword || !data.confirmPassword) {
			logger.warn("Reset password: Missing required fields.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Token and new passwords are required"
			);
		}

		if (data.newPassword !== data.confirmPassword) {
			logger.warn("Reset password: Passwords do not match.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Passwords do not match"
			);
		}

		const user = await User.findOne({
			forgotPasswordToken: data.token,
			forgotPasswordExpires: { $gt: Date.now() },
		});
		if (!user) {
			logger.warn(
				`Reset password failed: Invalid or expired token (${data.token})`
			);
			return sendResponse(
				res,
				400,
				false,
				null,
				"Invalid or expired token"
			);
		}

		const salt = await bcrypt.genSalt(10);
		user.password = await bcrypt.hash(data.newPassword, salt);
		user.forgotPasswordToken = undefined;
		user.forgotPasswordExpires = undefined;
		await user.save();

		logger.info(`Password reset successful for user: ${user._id}`);
		return sendResponse(res, 200, true, null, "Password reset successful");
	} catch (err) {
		logger.error(`Error in resetPassword: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ===========================
// Two-Factor Authentication (OTP)
// ===========================

// POST /api/v1/auth/send-otp
export const sendTwoFactorOTP = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			logger.warn("Send OTP: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const user = await User.findOne({ email });
		if (!user) {
			logger.warn(`Send OTP: User not found for email ${email}`);
			return sendResponse(res, 400, false, null, "User not found");
		}

		// Generate a 6-digit OTP that expires in 5 minutes
		const otp = Math.floor(100000 + Math.random() * 900000).toString();
		user.twoFactorOTP = otp;
		user.twoFactorOTPExpires = Date.now() + 5 * 60 * 1000;
		await user.save();

		await sendUserTwoFactorOTPEmail(user.email, otp);

		logger.info(`OTP sent for 2FA to user: ${user._id}`);
		return sendResponse(res, 200, true, null, "OTP sent to email");
	} catch (err) {
		logger.error(`Error in sendTwoFactorOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v1/auth/verify-otp
export const verifyTwoFactorOTP = async (req, res) => {
	try {
		const { email, otp } = req.body;
		if (!email || !otp) {
			logger.warn("Verify OTP: Email or OTP missing.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Email and OTP are required"
			);
		}
		const user = await User.findOne({ email });
		if (
			!user ||
			!user.twoFactorOTP ||
			user.twoFactorOTPExpires < Date.now()
		) {
			logger.warn(
				`Verify OTP failed: OTP invalid or expired for ${email}`
			);
			return sendResponse(
				res,
				400,
				false,
				null,
				"OTP is invalid or expired"
			);
		}
		if (user.twoFactorOTP !== otp) {
			logger.warn(
				`Verify OTP failed: Provided OTP does not match for ${email}`
			);
			return sendResponse(res, 400, false, null, "OTP does not match");
		}
		// Clear OTP after successful verification
		user.twoFactorOTP = undefined;
		user.twoFactorOTPExpires = undefined;
		await user.save();

		// NEW: Generate JWT token and set it in cookies
		const token = generateUserToken({ id: user._id, email: user.email });
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000, // 1 hour
		};
		res.cookie("user-token", token, cookieOptions);

		logger.info(`OTP verified for user: ${user._id} and token issued`);
		return sendResponse(
			res,
			200,
			true,
			{ token },
			"OTP verified successfully; token issued"
		);
	} catch (err) {
		logger.error(`Error in verifyTwoFactorOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ------------------------------
// Get Verification Status
// ------------------------------
// GET /api/v1/auth/verification-status
export const getVerificationStatus = async (req, res) => {
	try {
		// Assumes req.user is set by an authentication middleware
		const user = await User.findById(req.user.id);
		if (!user) {
			logger.warn(
				`User not found for verification status: ${req.user.id}`
			);
			return sendResponse(res, 404, false, null, "User not found");
		}
		const status = {
			verified: user.isVerified,
			message: user.isVerified
				? "Email is verified"
				: "Email is not verified. Please verify your email.",
		};
		logger.info(`Verification status retrieved for user: ${user._id}`);
		return sendResponse(
			res,
			200,
			true,
			status,
			"Verification status retrieved"
		);
	} catch (err) {
		logger.error(`Error in getVerificationStatus: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Enable two-factor authentication for user
export const enableTwoFactorAuth = async (req, res) => {
	try {
		// Assume req.user is set by your user authentication middleware
		const user = await User.findById(req.user.id);
		if (!user) {
			logger.warn(
				`User not found for enabling two-factor: ${req.user.id}`
			);
			return sendResponse(res, 404, false, null, "User not found");
		}
		user.twoFactorEnabled = true;
		await user.save();
		logger.info(`Two-factor authentication enabled for user: ${user._id}`);
		return sendResponse(
			res,
			200,
			true,
			null,
			"Two-factor authentication enabled"
		);
	} catch (err) {
		logger.error(`Error in enableTwoFactorAuth: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Disable two-factor authentication for user
export const disableTwoFactorAuth = async (req, res) => {
	try {
		const user = await User.findById(req.user.id);
		if (!user) {
			logger.warn(
				`User not found for disabling two-factor: ${req.user.id}`
			);
			return sendResponse(res, 404, false, null, "User not found");
		}
		user.twoFactorEnabled = false;
		await user.save();
		logger.info(`Two-factor authentication disabled for user: ${user._id}`);
		return sendResponse(
			res,
			200,
			true,
			null,
			"Two-factor authentication disabled"
		);
	} catch (err) {
		logger.error(`Error in disableTwoFactorAuth: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ---------- New OIDC Endpoints for Users ----------

// OIDC Authorization Endpoint for Users
// GET /api/v{version}/oidc/user/authorize?client_id=...&redirect_uri=...&response_type=code&state=...
export const oidcAuthorizeUser = async (req, res) => {
	try {
		const { client_id, redirect_uri, response_type, state } = req.query;
		if (!client_id || !redirect_uri || response_type !== "code") {
			return sendResponse(
				res,
				400,
				false,
				null,
				"Missing or invalid OIDC parameters"
			);
		}
		// Ensure the user is authenticated (set by userProtect middleware)
		if (!req.user) {
			return sendResponse(
				res,
				401,
				false,
				null,
				"User not authenticated"
			);
		}
		// Log the client_id along with the authenticated user
		logger.info(
			`OIDC authorize request from client: ${client_id} for user: ${req.user.id}`
		);

		// Generate an authorization code (for demonstration, we use a token; in production, store this with expiration)
		const authCode = generateToken();
		logger.info(
			`Generated OIDC auth code ${authCode} for user: ${req.user.id} and client: ${client_id}`
		);

		// Redirect back to the client with the code and state
		const redirectUrl = `${redirect_uri}?code=${authCode}&state=${state}`;
		return res.redirect(redirectUrl);
	} catch (err) {
		logger.error(`Error in oidcAuthorizeUser: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// OIDC Token Endpoint for Users
// POST /api/v{version}/oidc/user/token
export const oidcTokenUser = async (req, res) => {
	try {
		// Expect parameters: code, client_id, client_secret, redirect_uri, grant_type
		const { code, client_id, client_secret, redirect_uri, grant_type } =
			req.body;
		if (
			grant_type !== "authorization_code" ||
			!code ||
			!client_id ||
			!client_secret ||
			!redirect_uri
		) {
			return sendResponse(
				res,
				400,
				false,
				null,
				"Missing or invalid token request parameters"
			);
		}
		// (In production, validate the authorization code and the client credentials here)
		logger.info(
			`OIDC token request from client: ${client_id} for user with code: ${code}`
		);

		// For demonstration, assume we can retrieve the user from the stored authorization code.
		// Here we use req.user if available; in a full implementation, you'd look up the code to get the user.
		const userId = req.user ? req.user.id : "dummyId";
		const userEmail = req.user ? req.user.email : "dummy@example.com";
		// Generate token and include client_id as the audience claim
		const token = generateUserToken({
			id: userId,
			email: userEmail,
			aud: client_id,
		});

		return res.json({
			access_token: token,
			token_type: "Bearer",
			expires_in: 3600,
		});
	} catch (err) {
		logger.error(`Error in oidcTokenUser: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// OIDC UserInfo Endpoint for Users
// GET /api/v{version}/oidc/user/userinfo
export const oidcUserUserInfo = async (req, res) => {
	try {
		// Assume userProtect middleware validated the access token and set req.user
		if (!req.user) {
			return res.status(401).json({ error: "Invalid token" });
		}
		return res.json({
			id: req.user.id,
			email: req.user.email,
			name: req.user.name,
			// Additional fields can be added here
		});
	} catch (err) {
		logger.error(`Error in oidcUserUserInfo: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
