// src/controllers/adminController.js

import bcrypt from "bcryptjs";
import _ from "lodash";
import { z } from "zod";
import Admin from "../models/Admin.js";
import Session from "../models/Session.js";
import { generateToken, verifyToken } from "../services/tokenServices.js";
import { sendResponse, formatError } from "../utils/helpers.js";

// Import loggers
import logger from "../utils/logger.js"; // Winston logger
import pinoLogger from "../utils/pinoLogger.js"; // Pino logger
import bunyanLogger from "../utils/bunyanLogger.js"; // Bunyan logger
import { authLogger } from "../utils/log4jsConfig.js"; // Log4js logger for authentication flows
import signale from "../utils/signaleLogger.js"; // Signale for development logs
import tracerLogger from "../utils/tracerLogger.js"; // Tracer for function call tracing

// ------------------------------
// Zod Schemas for Admin Actions
// ------------------------------

const adminRegisterSchema = z.object({
	name: z.string().min(1, { message: "Name is required" }),
	email: z.string().email({ message: "Invalid email format" }),
	password: z
		.string()
		.min(6, { message: "Password must be at least 6 characters long" }),
	confirmPassword: z
		.string()
		.min(6, {
			message: "Confirm password must be at least 6 characters long",
		}),
	adminKey: z.string().min(1, { message: "Admin key is required" }),
	role: z.enum(["Admin", "Super Admin", "Moderator"]),
	permissions: z.array(z.string()).optional(),
	accessLevel: z.number().min(1).max(5).optional(),
	dateOfBirth: z.string().optional(),
	emergencyRecoveryContact: z.string().optional(),
	// Optional boolean flags
	canManageUsers: z.boolean().optional(),
	canManageContent: z.boolean().optional(),
	canManagePayments: z.boolean().optional(),
	canViewReports: z.boolean().optional(),
	canApproveNewAdmins: z.boolean().optional(),
	canSuspendUsers: z.boolean().optional(),
	canDeleteData: z.boolean().optional(),
	canExportData: z.boolean().optional(),
	superAdminKey: z.string().optional(),
	canPromoteDemoteAdmins: z.boolean().optional(),
	canModifyAdminPermissions: z.boolean().optional(),
	canOverrideSecuritySettings: z.boolean().optional(),
});

const adminLoginSchema = z.object({
	email: z.string().email({ message: "Invalid email format" }),
	password: z.string().min(1, { message: "Password is required" }),
});

// Helper to extract session data
const getSessionData = (req, token) => ({
	ipAddress:
		req.headers["x-forwarded-for"] || req.socket.remoteAddress || "Unknown",
	location: "Unknown",
	userAgent: req.headers["user-agent"] || "Unknown",
	token,
});

// ------------------------------
// Admin Controller Functions
// ------------------------------

// Register a new admin
export const registerAdmin = async (req, res) => {
	try {
		const data = _.pick(req.body, [
			"name",
			"email",
			"password",
			"confirmPassword",
			"adminKey",
			"role",
			"permissions",
			"accessLevel",
			"dateOfBirth",
			"emergencyRecoveryContact",
		]);
		const parsedData = adminRegisterSchema.parse(data);

		// Check if passwords match
		if (parsedData.password !== parsedData.confirmPassword) {
			authLogger.warn(
				"Admin registration failed: Passwords do not match."
			);
			return sendResponse(
				res,
				400,
				false,
				null,
				"Passwords do not match"
			);
		}
		// Remove confirmPassword from parsed data
		delete parsedData.confirmPassword;

		// Validate admin key
		if (
			parsedData.role !== "Super Admin" &&
			parsedData.adminKey !== process.env.ADMIN_KEY
		) {
			authLogger.warn(`Invalid admin key for ${parsedData.email}`);
			return sendResponse(res, 401, false, null, "Invalid admin key");
		}
		if (
			parsedData.role === "Super Admin" &&
			parsedData.superAdminKey !== process.env.SUPER_ADMIN_KEY
		) {
			authLogger.warn(`Invalid super admin key for ${parsedData.email}`);
			return sendResponse(
				res,
				401,
				false,
				null,
				"Invalid super admin key"
			);
		}

		// Check if admin exists
		let admin = await Admin.findOne({ email: parsedData.email });
		if (admin) {
			authLogger.warn(
				`Admin with email ${parsedData.email} already exists.`
			);
			return sendResponse(res, 400, false, null, "Admin already exists");
		}

		// Hash the password
		const salt = await bcrypt.genSalt(10);
		parsedData.password = await bcrypt.hash(parsedData.password, salt);

		// Create admin
		admin = await Admin.create(parsedData);

		// Generate token and set cookie
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

		// Create a session record
		await Session.create({
			user: admin._id,
			userModel: "Admin",
			...getSessionData(req, token),
		});

		// Logging messages
		logger.info(`Admin registered: ${admin._id}`);
		pinoLogger.info({ adminId: admin._id }, "Pino: New admin registered");
		bunyanLogger.info(
			{ adminId: admin._id },
			"Admin registration successful"
		);
		signale.success(`Admin ${admin.email} registered successfully.`);
		tracerLogger.trace(`registerAdmin executed for admin ${admin._id}`);

		return sendResponse(
			res,
			201,
			true,
			_.pick(admin, [
				"_id",
				"name",
				"email",
				"role",
				"accessLevel",
				"permissions",
			]),
			"Admin registered successfully"
		);
	} catch (err) {
		if (err instanceof z.ZodError) {
			authLogger.error("Validation error during admin registration.");
			return res
				.status(400)
				.json({ success: false, errors: formatError(err.errors) });
		}
		logger.error(`Error in registerAdmin: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Login admin
export const loginAdmin = async (req, res) => {
	try {
		const credentials = _.pick(req.body, ["email", "password"]);
		const parsedCreds = adminLoginSchema.parse(credentials);
		const admin = await Admin.findOne({ email: parsedCreds.email });
		if (!admin) {
			authLogger.warn(
				`Admin login failed: ${parsedCreds.email} not found.`
			);
			return sendResponse(res, 401, false, null, "Invalid credentials");
		}
		const isMatch = await bcrypt.compare(
			parsedCreds.password,
			admin.password
		);
		if (!isMatch) {
			authLogger.warn(
				`Admin login failed: Incorrect password for ${parsedCreds.email}`
			);
			return sendResponse(res, 401, false, null, "Invalid credentials");
		}

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

		logger.info(`Admin logged in: ${admin._id}`);
		pinoLogger.info({ adminId: admin._id }, "Pino: Admin logged in");
		bunyanLogger.info({ adminId: admin._id }, "Admin login successful");
		signale.success(`Admin ${admin.email} logged in successfully.`);
		tracerLogger.trace(`loginAdmin executed for admin ${admin._id}`);

		return sendResponse(
			res,
			200,
			true,
			_.pick(admin, [
				"_id",
				"name",
				"email",
				"role",
				"accessLevel",
				"permissions",
			]),
			"Login successful"
		);
	} catch (err) {
		if (err instanceof z.ZodError) {
			authLogger.error("Validation error during admin login.");
			return res
				.status(400)
				.json({ success: false, errors: formatError(err.errors) });
		}
		logger.error(`Error in loginAdmin: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Validate admin token
export const validateAdminToken = async (req, res) => {
	try {
		let token;
		if (req.cookies && req.cookies.token) {
			token = req.cookies.token;
		} else if (
			req.headers.authorization &&
			req.headers.authorization.startsWith("Bearer ")
		) {
			token = req.headers.authorization.split(" ")[1];
		}
		if (!token) {
			authLogger.warn("No token provided for admin validation.");
			return sendResponse(res, 401, false, null, "No token provided");
		}
		const decoded = verifyToken(token);
		if (!decoded) {
			authLogger.warn("Invalid admin token provided.");
			return sendResponse(res, 401, false, null, "Invalid token");
		}
		logger.info(`Admin token validated: ${decoded.id}`);
		pinoLogger.info({ adminId: decoded.id }, "Pino: Admin token validated");
		bunyanLogger.info({ adminId: decoded.id }, "Admin token is valid");
		signale.success("Admin token is valid");
		tracerLogger.trace("validateAdminToken executed");

		return sendResponse(res, 200, true, decoded, "Token is valid");
	} catch (err) {
		logger.error(`Error in validateAdminToken: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Logout admin
export const logoutAdmin = async (req, res) => {
	try {
		res.clearCookie("token");
		logger.info(
			`Admin logged out: ${req.user ? req.user.id : "unknown admin"}`
		);
		signale.success("Admin logged out successfully.");
		tracerLogger.trace(
			`logoutAdmin executed for admin ${
				req.user ? req.user.id : "unknown"
			}`
		);
		return sendResponse(res, 200, true, null, "Logged out successfully");
	} catch (err) {
		logger.error(`Error in logoutAdmin: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Retrieve admin profile
export const getAdminProfile = async (req, res) => {
	try {
		const admin = await Admin.findById(req.user.id).select("-password");
		if (!admin) {
			authLogger.warn(
				`Admin not found for profile retrieval: ${req.user.id}`
			);
			return sendResponse(res, 404, false, null, "Admin not found");
		}
		logger.info(`Admin profile retrieved: ${req.user.id}`);
		return sendResponse(res, 200, true, admin, "Admin profile retrieved");
	} catch (err) {
		logger.error(`Error in getAdminProfile: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Update admin profile
export const updateAdminProfile = async (req, res) => {
	try {
		const allowedFields = [
			"name",
			"email",
			"password",
			"dateOfBirth",
			"emergencyRecoveryContact",
			"role",
			"permissions",
			"accessLevel",
		];
		const updateData = _.pick(req.body, allowedFields);
		if (updateData.password) {
			const salt = await bcrypt.genSalt(10);
			updateData.password = await bcrypt.hash(updateData.password, salt);
		}
		const admin = await Admin.findByIdAndUpdate(req.user.id, updateData, {
			new: true,
		});
		if (!admin) {
			authLogger.warn(`Admin not found for update: ${req.user.id}`);
			return sendResponse(res, 404, false, null, "Admin not found");
		}
		logger.info(`Admin profile updated: ${req.user.id}`);
		return sendResponse(
			res,
			200,
			true,
			_.pick(admin, [
				"_id",
				"name",
				"email",
				"role",
				"accessLevel",
				"permissions",
			]),
			"Admin profile updated successfully"
		);
	} catch (err) {
		logger.error(`Error in updateAdminProfile: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};

// Delete admin account
export const deleteAdminAccount = async (req, res) => {
	try {
		await Admin.findByIdAndDelete(req.user.id);
		logger.info(`Admin account deleted: ${req.user.id}`);
		signale.success(`Admin account ${req.user.id} deleted successfully.`);
		return sendResponse(
			res,
			200,
			true,
			null,
			"Admin account deleted successfully"
		);
	} catch (err) {
		logger.error(`Error in deleteAdminAccount: ${err.message}`);
		return sendResponse(res, 500, false, null, "Server error");
	}
};
