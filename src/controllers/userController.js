// src/controllers/userController.js

import bcrypt from "bcryptjs";
import _ from "lodash";
import { z } from "zod";
import User from "../models/User.js";
import Session from "../models/Session.js";
import { generateToken, verifyToken } from "../services/tokenServices.js";
import { sendResponse, formatError } from "../utils/helpers.js";

// Import loggers
import logger from "../utils/logger.js";             // Winston logger
import pinoLogger from "../utils/pinoLogger.js";        // Pino logger
import bunyanLogger from "../utils/bunyanLogger.js";    // Bunyan logger
import { authLogger } from "../utils/log4jsConfig.js";  // Log4js logger for auth flows
import signale from "../utils/signaleLogger.js";        // Signale for development logs
import tracerLogger from "../utils/tracerLogger.js";    // Tracer logger

// --------------------------
// Zod Schemas
// --------------------------

const userRegisterSchema = z.object({
  name: z.string().min(1, { message: "Name is required" }),
  email: z.string().email({ message: "Invalid email format" }),
  password: z.string().min(6, { message: "Password must be at least 6 characters long" }),
  confirmPassword: z.string().min(6, { message: "Confirm password must be at least 6 characters long" }),
  dateOfBirth: z.string().optional(),
  emergencyRecoveryContact: z.string().optional(),
});

const userLoginSchema = z.object({
  email: z.string().email({ message: "Invalid email format" }),
  password: z.string().min(1, { message: "Password is required" }),
});

// --------------------------
// Helper to Extract Session Data
// --------------------------

const getSessionData = (req, token) => ({
  ipAddress: req.headers["x-forwarded-for"] || req.socket.remoteAddress || "Unknown",
  location: "Unknown",
  userAgent: req.headers["user-agent"] || "Unknown",
  token,
});

// --------------------------
// Controller Functions
// --------------------------

// Register new user
export const registerUser = async (req, res) => {
  try {
    const allowedFields = [
      "name",
      "email",
      "password",
      "confirmPassword",
      "dateOfBirth",
      "emergencyRecoveryContact",
    ];
    const data = _.pick(req.body, allowedFields);
    const parsedData = userRegisterSchema.parse(data);

    // Check if passwords match
    if (parsedData.password !== parsedData.confirmPassword) {
      authLogger.warn("Registration failed: Passwords do not match.");
      return sendResponse(res, 400, false, null, "Passwords do not match");
    }
    delete parsedData.confirmPassword;

    // Check if user exists
    let user = await User.findOne({ email: parsedData.email });
    if (user) {
      authLogger.warn(`User registration failed: ${parsedData.email} already exists.`);
      return sendResponse(res, 400, false, null, "User already exists");
    }

    // Hash password
    const salt = await bcrypt.genSalt(12);
    parsedData.password = await bcrypt.hash(parsedData.password, salt);

    // Create user (Note: new users are unverified by default)
    user = await User.create(parsedData);

    // Log registration
    logger.info(`User registered: ${user._id}`);
    pinoLogger.info({ userId: user._id }, "Pino: New user registered");
    bunyanLogger.info({ userId: user._id }, "User registration successful");
    signale.success(`User ${user.email} registered successfully.`);
    tracerLogger.trace(`registerUser executed for user ${user._id}`);

    return sendResponse(
      res,
      201,
      true,
      _.pick(user, ["_id", "name", "email", "dateOfBirth", "emergencyRecoveryContact"]),
      "User registered successfully. Please verify your email to activate your account."
    );
  } catch (err) {
    if (err instanceof z.ZodError) {
      authLogger.error("Validation error during user registration.");
      return res.status(400).json({ success: false, errors: formatError(err.errors) });
    }
    logger.error(`Error in registerUser: ${err.message}`);
    return sendResponse(res, 500, false, null, "Server error");
  }
};

// Login user (requires email verification)
export const loginUser = async (req, res) => {
  try {
    const credentials = _.pick(req.body, ["email", "password"]);
    const parsedCreds = userLoginSchema.parse(credentials);
    const user = await User.findOne({ email: parsedCreds.email });
    if (!user) {
      authLogger.warn(`Login failed: User ${parsedCreds.email} not found.`);
      return sendResponse(res, 401, false, null, "Invalid credentials");
    }
    if (!user.isVerified) {
      authLogger.warn(`Login failed: User ${parsedCreds.email} not verified.`);
      return sendResponse(res, 403, false, null, "Please verify your email before logging in.");
    }
    const isMatch = await bcrypt.compare(parsedCreds.password, user.password);
    if (!isMatch) {
      authLogger.warn(`Login failed: Incorrect password for ${parsedCreds.email}.`);
      return sendResponse(res, 401, false, null, "Invalid credentials");
    }

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

    await Session.create({
      user: user._id,
      userModel: "User",
      ...getSessionData(req, token),
    });

    logger.info(`User logged in: ${user._id}`);
    pinoLogger.info({ userId: user._id }, "Pino: User logged in");
    bunyanLogger.info({ userId: user._id }, "User login successful");
    signale.success(`User ${user.email} logged in.`);
    tracerLogger.trace(`loginUser executed for user ${user._id}`);

    return sendResponse(
      res,
      200,
      true,
      _.pick(user, ["_id", "name", "email", "dateOfBirth", "emergencyRecoveryContact"]),
      "Login successful"
    );
  } catch (err) {
    if (err instanceof z.ZodError) {
      authLogger.error("Validation error during user login.");
      return res.status(400).json({ success: false, errors: formatError(err.errors) });
    }
    logger.error(`Error in loginUser: ${err.message}`);
    return sendResponse(res, 500, false, null, "Server error");
  }
};

// Validate user token
export const validateUserToken = async (req, res) => {
  try {
    let token;
    if (req.cookies && req.cookies.token) {
      token = req.cookies.token;
    } else if (req.headers.authorization && req.headers.authorization.startsWith("Bearer ")) {
      token = req.headers.authorization.split(" ")[1];
    }
    if (!token) {
      authLogger.warn("No token provided for user validation.");
      return sendResponse(res, 401, false, null, "No token provided");
    }
    const decoded = verifyToken(token);
    if (!decoded) {
      authLogger.warn("Invalid token provided for user.");
      return sendResponse(res, 401, false, null, "Invalid token");
    }
    logger.info("User token validated successfully");
    pinoLogger.info("Pino: User token validated");
    signale.success("User token is valid");
    tracerLogger.trace("validateUserToken executed");

    return sendResponse(res, 200, true, { token }, "Token is valid");
  } catch (err) {
    logger.error(`Error in validateUserToken: ${err.message}`);
    return sendResponse(res, 500, false, null, "Server error");
  }
};

// Logout user
export const logoutUser = async (req, res) => {
  try {
    res.clearCookie("token");
    logger.info(`User logged out: ${req.user ? req.user.id : "unknown user"}`);
    signale.success("User logged out successfully.");
    tracerLogger.trace(`logoutUser executed for user ${req.user ? req.user.id : "unknown"}`);
    return sendResponse(res, 200, true, null, "Logged out successfully");
  } catch (err) {
    logger.error(`Error in logoutUser: ${err.message}`);
    return sendResponse(res, 500, false, null, "Server error");
  }
};

// Retrieve user profile
export const getUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    if (!user) {
      authLogger.warn(`User not found for profile retrieval: ${req.user.id}`);
      return sendResponse(res, 404, false, null, "User not found");
    }
    logger.info(`User profile retrieved: ${req.user.id}`);
    return sendResponse(res, 200, true, user, "User profile retrieved");
  } catch (err) {
    logger.error(`Error in getUserProfile: ${err.message}`);
    return sendResponse(res, 500, false, null, "Server error");
  }
};

// Update user profile
export const updateUserProfile = async (req, res) => {
  try {
    const allowedFields = ["name", "email", "password", "dateOfBirth", "emergencyRecoveryContact"];
    const updateData = _.pick(req.body, allowedFields);

    if (updateData.password) {
      const salt = await bcrypt.genSalt(12);
      updateData.password = await bcrypt.hash(updateData.password, salt);
    }
    const user = await User.findByIdAndUpdate(req.user.id, updateData, { new: true });
    if (!user) {
      authLogger.warn(`User not found for update: ${req.user.id}`);
      return sendResponse(res, 404, false, null, "User not found");
    }
    logger.info(`User profile updated: ${req.user.id}`);
    return sendResponse(
      res,
      200,
      true,
      _.pick(user, ["_id", "name", "email", "dateOfBirth", "emergencyRecoveryContact"]),
      "User profile updated successfully"
    );
  } catch (err) {
    logger.error(`Error in updateUserProfile: ${err.message}`);
    return sendResponse(res, 500, false, null, "Server error");
  }
};

// Delete user account
export const deleteUserAccount = async (req, res) => {
  try {
    await User.findByIdAndDelete(req.user.id);
    logger.info(`User account deleted: ${req.user.id}`);
    signale.success(`User account ${req.user.id} deleted successfully.`);
    return sendResponse(res, 200, true, null, "User account deleted successfully");
  } catch (err) {
    logger.error(`Error in deleteUserAccount: ${err.message}`);
    return sendResponse(res, 500, false, null, "Server error");
  }
};
