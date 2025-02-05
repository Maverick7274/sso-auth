// src/controllers/adminExtraController.js

import crypto from "crypto";
import bcrypt from "bcryptjs";
import _ from "lodash";
import Admin from "../models/Admin.js";
import { sendResponse } from "../utils/helpers.js";
import {
	sendVerificationEmail,
	sendResetPasswordEmail,
	sendTwoFactorOTPEmail,
	sendLoginOTPEmail,
} from "../services/emailService.js";

// Import loggers
import logger from "../utils/logger.js";
import pinoLogger from "../utils/pinoLogger.js";
import bunyanLogger from "../utils/bunyanLogger.js";
import { authLogger } from "../utils/log4jsConfig.js";
import signale from "../utils/signaleLogger.js";
import tracerLogger from "../utils/tracerLogger.js";

// Helper to generate a random token
const generateToken = () => crypto.randomBytes(20).toString("hex");

// ------------------------------------------------------
// Verify Email
// ------------------------------------------------------
// GET /api/v1/admin/verify-email?token=XYZ
export const verifyEmail = async (req, res) => {
	try {
		const { token } = req.query;
		if (!token) {
			authLogger.warn("Admin verification token missing in request.");
			return sendResponse(res, 400, false, null, "Token is required");
		}
		const admin = await Admin.findOne({
			emailVerificationToken: token,
			emailVerificationExpires: { $gt: Date.now() },
		});
		if (!admin) {
			authLogger.warn(`Invalid or expired token: ${token}`);
			return sendResponse(
				res,
				400,
				false,
				null,
				"Invalid or expired token"
			);
		}
		admin.isVerified = true;
		admin.emailVerificationToken = undefined;
		admin.emailVerificationExpires = undefined;
		await admin.save();

		logger.info(`Admin email verified: ${admin._id}`);
		pinoLogger.info({ adminId: admin._id }, "Pino: Email verified");
		bunyanLogger.info(
			{ adminId: admin._id },
			"Email verified successfully"
		);
		signale.success(`Admin email verified successfully for ${admin.email}`);
		tracerLogger.trace(`verifyEmail executed for admin ${admin._id}`);

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

// POST /api/v1/admin/resend-verification
export const resendVerificationEmail = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			authLogger.warn("Resend verification: Email missing in request.");
			return sendResponse(res, 400, false, null, "Email is required");
		}
		const admin = await Admin.findOne({ email });
		if (!admin) {
			authLogger.warn(
				`Resend verification failed: Admin not found (${email})`
			);
			return sendResponse(res, 400, false, null, "Admin not found");
		}
		if (admin.isVerified) {
			authLogger.info(
				`Admin ${email} already verified; no need to resend email.`
			);
			return sendResponse(
				res,
				400,
				false,
				null,
				"Email already verified"
			);
		}
		const token = generateToken();
		admin.emailVerificationToken = token;
		// For admins, you might want a different expiration (e.g., 15 minutes)
		admin.emailVerificationExpires = Date.now() + 15 * 60 * 1000;
		await admin.save();

		await sendVerificationEmail(admin.email, token);

		logger.info(`Resent verification email to admin: ${admin._id}`);
		signale.success(`Verification email resent to ${admin.email}`);
		tracerLogger.trace(
			`resendVerificationEmail executed for admin ${admin._id}`
		);

		return sendResponse(res, 200, true, null, "Verification email sent");
	} catch (err) {
		logger.error(`Error in resendVerificationEmail: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ------------------------------------------------------
// Forgot Password & Reset Password
// ------------------------------------------------------

// POST /api/v1/admin/forgot-password
export const forgotPassword = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			authLogger.warn("Forgot password: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}
		const admin = await Admin.findOne({ email });
		if (!admin) {
			authLogger.warn(
				`Forgot password: Admin not found for email ${email}`
			);
			return sendResponse(res, 400, false, null, "Admin not found");
		}
		const token = generateToken();
		admin.forgotPasswordToken = token;
		admin.forgotPasswordExpires = Date.now() + 60 * 60 * 1000;
		await admin.save();

		await sendResetPasswordEmail(admin.email, token);

		logger.info(`Password reset email sent for admin: ${admin._id}`);
		signale.success(`Password reset email sent to ${admin.email}`);
		tracerLogger.trace(`forgotPassword executed for admin ${admin._id}`);

		return sendResponse(res, 200, true, null, "Password reset email sent");
	} catch (err) {
		logger.error(`Error in forgotPassword: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v1/admin/reset-password
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

		const admin = await Admin.findOne({
			forgotPasswordToken: data.token,
			forgotPasswordExpires: { $gt: Date.now() },
		});
		if (!admin) {
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
		admin.password = await bcrypt.hash(data.newPassword, salt);
		admin.forgotPasswordToken = undefined;
		admin.forgotPasswordExpires = undefined;
		await admin.save();

		logger.info(`Password reset successful for admin: ${admin._id}`);
		pinoLogger.info({ adminId: admin._id }, "Pino: Password reset");
		signale.success(`Password reset successful for ${admin.email}`);
		tracerLogger.trace(`resetPassword executed for admin ${admin._id}`);

		return sendResponse(res, 200, true, null, "Password reset successful");
	} catch (err) {
		logger.error(`Error in resetPassword: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// ------------------------------------------------------
// Two-Factor Authentication (OTP) for Admin
// ------------------------------------------------------

// POST /api/v1/admin/send-twofactor-otp
export const sendTwoFactorOTP = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			authLogger.warn("Send 2FA OTP: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}
		const admin = await Admin.findOne({ email });
		if (!admin) {
			authLogger.warn(`Send 2FA OTP: Admin not found for email ${email}`);
			return sendResponse(res, 400, false, null, "Admin not found");
		}

		const plainOTP = Math.floor(100000 + Math.random() * 900000).toString();
		const salt = await bcrypt.genSalt(10);
		const hashedOTP = await bcrypt.hash(plainOTP, salt);

		admin.twoFactorOTP = hashedOTP;
		admin.twoFactorOTPExpires = Date.now() + 5 * 60 * 1000;
		await admin.save();

		await sendTwoFactorOTPEmail(admin.email, plainOTP);

		logger.info(`2FA OTP sent for admin: ${admin._id}`);
		pinoLogger.info({ adminId: admin._id }, "Pino: 2FA OTP sent");
		signale.success(`2FA OTP sent to ${admin.email}`);
		tracerLogger.trace(`sendTwoFactorOTP executed for admin ${admin._id}`);

		return sendResponse(res, 200, true, null, "2FA OTP sent to email");
	} catch (err) {
		logger.error(`Error in sendTwoFactorOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v1/admin/verify-twofactor-otp
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
		const admin = await Admin.findOne({ email });
		if (
			!admin ||
			!admin.twoFactorOTP ||
			admin.twoFactorOTPExpires < Date.now()
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
		const isMatch = await bcrypt.compare(otp, admin.twoFactorOTP);
		if (!isMatch) {
			authLogger.warn(
				`Verify 2FA OTP failed: Provided OTP does not match for ${email}`
			);
			return sendResponse(res, 400, false, null, "OTP does not match");
		}

		admin.twoFactorOTP = undefined;
		admin.twoFactorOTPExpires = undefined;
		await admin.save();

		logger.info(`2FA OTP verified for admin: ${admin._id}`);
		pinoLogger.info({ adminId: admin._id }, "Pino: 2FA OTP verified");
		signale.success(`2FA OTP verified successfully for ${admin.email}`);
		tracerLogger.trace(
			`verifyTwoFactorOTP executed for admin ${admin._id}`
		);

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

// ------------------------------------------------------
// Passwordless Login with OTP for Admin
// ------------------------------------------------------

// POST /api/v1/admin/send-login-otp
export const sendLoginOTP = async (req, res) => {
	try {
		const { email } = req.body;
		if (!email) {
			authLogger.warn("Send login OTP: Email missing.");
			return sendResponse(res, 400, false, null, "Email is required");
		}
		const admin = await Admin.findOne({ email });
		if (!admin) {
			authLogger.warn(
				`Send login OTP: Admin not found for email ${email}`
			);
			return sendResponse(res, 400, false, null, "Admin not found");
		}
		if (!admin.isVerified) {
			authLogger.warn(`Send login OTP: Admin ${email} not verified.`);
			return sendResponse(
				res,
				403,
				false,
				null,
				"Please verify your email first"
			);
		}

		const plainOTP = Math.floor(100000 + Math.random() * 900000).toString();
		const salt = await bcrypt.genSalt(10);
		const hashedOTP = await bcrypt.hash(plainOTP, salt);

		admin.loginOTP = hashedOTP;
		admin.loginOTPExpires = Date.now() + 5 * 60 * 1000;
		await admin.save();

		await sendLoginOTPEmail(admin.email, plainOTP);

		logger.info(`Login OTP sent for admin: ${admin._id}`);
		pinoLogger.info({ adminId: admin._id }, "Pino: Login OTP sent");
		signale.success(`Login OTP sent to ${admin.email}`);
		tracerLogger.trace(`sendLoginOTP executed for admin ${admin._id}`);

		return sendResponse(res, 200, true, null, "Login OTP sent to email");
	} catch (err) {
		logger.error(`Error in sendLoginOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// POST /api/v1/admin/verify-login-otp
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
		const admin = await Admin.findOne({ email });
		if (!admin || !admin.loginOTP || admin.loginOTPExpires < Date.now()) {
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
		const isMatch = await bcrypt.compare(otp, admin.loginOTP);
		if (!isMatch) {
			authLogger.warn(
				`Verify login OTP failed: OTP does not match for ${email}`
			);
			return sendResponse(res, 400, false, null, "OTP does not match");
		}
		admin.loginOTP = undefined;
		admin.loginOTPExpires = undefined;
		await admin.save();

		const token = generateToken({
			id: admin._id,
			email: admin.email,
			isAdmin: admin.isAdmin,
		});
		const cookieOptions = {
			httpOnly: true,
			secure: process.env.NODE_ENV === "production",
			sameSite: "strict",
			maxAge: 60 * 60 * 1000,
		};
		res.cookie("token", token, cookieOptions);

		await Session.create({
			user: admin._id,
			userModel: "Admin",
			...getSessionData(req, token),
		});

		logger.info(`Passwordless login successful for admin: ${admin._id}`);
		pinoLogger.info(
			{ adminId: admin._id },
			"Pino: Passwordless login successful"
		);
		bunyanLogger.info(
			{ adminId: admin._id },
			"Passwordless login successful"
		);
		signale.success(`Admin ${admin.email} logged in via OTP successfully.`);
		tracerLogger.trace(`verifyLoginOTP executed for admin ${admin._id}`);

		return sendResponse(
			res,
			200,
			true,
			_.pick(admin, ["_id", "name", "email", "role"]),
			"Login successful via OTP"
		);
	} catch (err) {
		logger.error(`Error in verifyLoginOTP: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
