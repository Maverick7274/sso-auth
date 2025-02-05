// src/controllers/userExtraController.js

import crypto from "crypto";
import bcrypt from "bcryptjs";
import _ from "lodash";
import User from "../models/User.js";
import { sendResponse } from "../utils/helpers.js";
import {
	sendVerificationEmail,
	sendResetPasswordEmail,
	sendTwoFactorOTPEmail,
	sendLoginOTPEmail, // Assume you have a separate email template for login OTP
} from "../services/emailService.js";

// Import loggers
import logger from "../utils/logger.js"; // Winston logger
import pinoLogger from "../utils/pinoLogger.js"; // Pino logger
import bunyanLogger from "../utils/bunyanLogger.js"; // Bunyan logger
import { authLogger } from "../utils/log4jsConfig.js"; // Log4js logger for auth flows
import signale from "../utils/signaleLogger.js"; // Signale for development logs
import tracerLogger from "../utils/tracerLogger.js"; // Tracer for function call tracing

// Helper to generate a random token (for email verification and password reset)
const generateToken = () => crypto.randomBytes(20).toString("hex");

// ----------------------------------------------------
// EMAIL VERIFICATION
// ----------------------------------------------------

// GET /api/v1/auth/verify-email?token=XYZ
export const verifyEmail = async (req, res) => {
	try {
		const { token } = req.query;
		if (!token) {
			authLogger.warn("Verification token missing in request.");
			return sendResponse(res, 400, false, null, "Token is required");
		}

		// Find the user with a matching, unexpired verification token
		const user = await User.findOne({
			emailVerificationToken: token,
			emailVerificationExpires: { $gt: Date.now() },
		});
		if (!user) {
			authLogger.warn(`Invalid or expired token: ${token}`);
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
		pinoLogger.info({ userId: user._id }, "Pino: Email verified");
		bunyanLogger.info({ userId: user._id }, "Email verified successfully");
		signale.success(`Email verified successfully for ${user.email}`);
		tracerLogger.trace(`verifyEmail executed for user ${user._id}`);

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
			authLogger.warn("Resend verification: Email missing in request.");
			return sendResponse(res, 400, false, null, "Email is required");
		}

		const user = await User.findOne({ email });
		if (!user) {
			authLogger.warn(
				`Resend verification failed: User not found (${email})`
			);
			return sendResponse(res, 400, false, null, "User not found");
		}
		if (user.isVerified) {
			authLogger.info(
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

		// Generate a new token (expires in 15 minutes)
		const token = generateToken();
		user.emailVerificationToken = token;
		user.emailVerificationExpires = Date.now() + 15 * 60 * 1000;
		await user.save();

		await sendVerificationEmail(user.email, token);

		logger.info(`Resent verification email to user: ${user._id}`);
		signale.success(`Verification email resent to ${user.email}`);
		tracerLogger.trace(
			`resendVerificationEmail executed for user ${user._id}`
		);

		return sendResponse(res, 200, true, null, "Verification email sent");
	} catch (err) {
		logger.error(`Error in resendVerificationEmail: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ----------------------------------------------------
// FORGOT PASSWORD & RESET PASSWORD
// ----------------------------------------------------

// POST /api/v1/auth/forgot-password
export const forgotPassword = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			authLogger.warn("Forgot password: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}
		const user = await User.findOne({ email });
		if (!user) {
			authLogger.warn(
				`Forgot password: User not found for email ${email}`
			);
			return sendResponse(res, 400, false, null, "User not found");
		}
		// Generate a reset token (expires in 1 hour)
		const token = generateToken();
		user.forgotPasswordToken = token;
		user.forgotPasswordExpires = Date.now() + 60 * 60 * 1000;
		await user.save();

		await sendResetPasswordEmail(user.email, token);

		logger.info(`Password reset email sent for user: ${user._id}`);
		signale.success(`Password reset email sent to ${user.email}`);
		tracerLogger.trace(`forgotPassword executed for user ${user._id}`);

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
			authLogger.warn("Reset password: Missing required fields.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Token and new passwords are required"
			);
		}
		if (data.newPassword !== data.confirmPassword) {
			authLogger.warn("Reset password: Passwords do not match.");
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
			authLogger.warn(
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

		const salt = await bcrypt.genSalt(12);
		user.password = await bcrypt.hash(data.newPassword, salt);
		user.forgotPasswordToken = undefined;
		user.forgotPasswordExpires = undefined;
		await user.save();

		logger.info(`Password reset successful for user: ${user._id}`);
		pinoLogger.info({ userId: user._id }, "Pino: Password reset");
		signale.success(`Password reset successful for ${user.email}`);
		tracerLogger.trace(`resetPassword executed for user ${user._id}`);

		return sendResponse(res, 200, true, null, "Password reset successful");
	} catch (err) {
		logger.error(`Error in resetPassword: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ----------------------------------------------------
// TWO-FCTOR AUTHENTICATION (OTP) Endpoints
// ----------------------------------------------------

// POST /api/v1/auth/send-twofactor-otp
export const sendTwoFactorOTP = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			authLogger.warn("Send 2FA OTP: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}
		const user = await User.findOne({ email });
		if (!user) {
			authLogger.warn(`Send 2FA OTP: User not found for email ${email}`);
			return sendResponse(res, 400, false, null, "User not found");
		}

		// Generate a 6-digit OTP
		const plainOTP = Math.floor(100000 + Math.random() * 900000).toString();
		// Hash the OTP before saving
		const salt = await bcrypt.genSalt(10);
		const hashedOTP = await bcrypt.hash(plainOTP, salt);

		user.twoFactorOTP = hashedOTP;
		user.twoFactorOTPExpires = Date.now() + 5 * 60 * 1000; // Expires in 5 minutes
		await user.save();

		await sendTwoFactorOTPEmail(user.email, plainOTP);

		logger.info(`2FA OTP sent for user: ${user._id}`);
		pinoLogger.info({ userId: user._id }, "Pino: 2FA OTP sent");
		signale.success(`2FA OTP sent to ${user.email}`);
		tracerLogger.trace(`sendTwoFactorOTP executed for user ${user._id}`);

		return sendResponse(res, 200, true, null, "2FA OTP sent to email");
	} catch (err) {
		logger.error(`Error in sendTwoFactorOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v1/auth/verify-twofactor-otp
export const verifyTwoFactorOTP = async (req, res) => {
	try {
		const { email, otp } = req.body;
		if (!email || !otp) {
			authLogger.warn("Verify 2FA OTP: Email or OTP missing.");
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
			authLogger.warn(
				`Verify 2FA OTP failed: OTP invalid or expired for ${email}`
			);
			return sendResponse(
				res,
				400,
				false,
				null,
				"OTP is invalid or expired"
			);
		}
		// Compare provided OTP with the stored hashed OTP
		const isMatch = await bcrypt.compare(otp, user.twoFactorOTP);
		if (!isMatch) {
			authLogger.warn(
				`Verify 2FA OTP failed: OTP does not match for ${email}`
			);
			return sendResponse(res, 400, false, null, "OTP does not match");
		}

		// Clear OTP after successful verification
		user.twoFactorOTP = undefined;
		user.twoFactorOTPExpires = undefined;
		await user.save();

		logger.info(`2FA OTP verified for user: ${user._id}`);
		pinoLogger.info({ userId: user._id }, "Pino: 2FA OTP verified");
		signale.success(`2FA OTP verified successfully for ${user.email}`);
		tracerLogger.trace(`verifyTwoFactorOTP executed for user ${user._id}`);

		return sendResponse(
			res,
			200,
			true,
			null,
			"2FA OTP verified successfully"
		);
	} catch (err) {
		logger.error(`Error in verifyTwoFactorOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ----------------------------------------------------
// PASSWORDLESS LOGIN WITH OTP Endpoints
// ----------------------------------------------------

// POST /api/v1/auth/send-login-otp
export const sendLoginOTP = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			authLogger.warn("Send login OTP: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}
		const user = await User.findOne({ email });
		if (!user) {
			authLogger.warn(
				`Send login OTP: User not found for email ${email}`
			);
			return sendResponse(res, 400, false, null, "User not found");
		}
		if (!user.isVerified) {
			authLogger.warn(`Send login OTP: User ${email} not verified.`);
			return sendResponse(
				res,
				403,
				false,
				null,
				"Please verify your email first"
			);
		}

		// Generate a 6-digit OTP for login
		const plainOTP = Math.floor(100000 + Math.random() * 900000).toString();
		const salt = await bcrypt.genSalt(10);
		const hashedOTP = await bcrypt.hash(plainOTP, salt);

		user.loginOTP = hashedOTP; // Save in a separate field for login OTP
		user.loginOTPExpires = Date.now() + 5 * 60 * 1000; // Expires in 5 minutes
		await user.save();

		// Send login OTP email (use a separate template if desired)
		await sendLoginOTPEmail(user.email, plainOTP);

		logger.info(`Login OTP sent for user: ${user._id}`);
		pinoLogger.info({ userId: user._id }, "Pino: Login OTP sent");
		signale.success(`Login OTP sent to ${user.email}`);
		tracerLogger.trace(`sendLoginOTP executed for user ${user._id}`);

		return sendResponse(res, 200, true, null, "Login OTP sent to email");
	} catch (err) {
		logger.error(`Error in sendLoginOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v1/auth/verify-login-otp
export const verifyLoginOTP = async (req, res) => {
	try {
		const { email, otp } = req.body;
		if (!email || !otp) {
			authLogger.warn("Verify login OTP: Email or OTP missing.");
			return sendResponse(
				res,
				400,
				false,
				null,
				"Email and OTP are required"
			);
		}
		const user = await User.findOne({ email });
		if (!user || !user.loginOTP || user.loginOTPExpires < Date.now()) {
			authLogger.warn(
				`Verify login OTP failed: OTP invalid or expired for ${email}`
			);
			return sendResponse(
				res,
				400,
				false,
				null,
				"OTP is invalid or expired"
			);
		}
		const isMatch = await bcrypt.compare(otp, user.loginOTP);
		if (!isMatch) {
			authLogger.warn(
				`Verify login OTP failed: OTP does not match for ${email}`
			);
			return sendResponse(res, 400, false, null, "OTP does not match");
		}

		// Clear login OTP after successful verification
		user.loginOTP = undefined;
		user.loginOTPExpires = undefined;
		await user.save();

		// Generate JWT token for passwordless login
		const token = generateToken({
			id: user._id,
			email: user.email,
			isAdmin: user.isAdmin,
		});
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000,
		};
		res.cookie("token", token, cookieOptions);

		// Create session record
		await Session.create({
			user: user._id,
			userModel: "User",
			...getSessionData(req, token),
		});

		logger.info(`Passwordless login successful for user: ${user._id}`);
		pinoLogger.info(
			{ userId: user._id },
			"Pino: Passwordless login successful"
		);
		bunyanLogger.info(
			{ userId: user._id },
			"Passwordless login successful"
		);
		signale.success(`User ${user.email} logged in via OTP successfully.`);
		tracerLogger.trace(`verifyLoginOTP executed for user ${user._id}`);

		return sendResponse(
			res,
			200,
			true,
			_.pick(user, [
				"_id",
				"name",
				"email",
				"dateOfBirth",
				"emergencyRecoveryContact",
			]),
			"Login successful via OTP"
		);
	} catch (err) {
		logger.error(`Error in verifyLoginOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
