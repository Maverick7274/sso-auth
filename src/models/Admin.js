// models/Admin.js
import mongoose from "mongoose";

// Define the Admin schema for the "admins" collection in MongoDB
const adminSchema = new mongoose.Schema(
	{
		// Admin's full name
		name: {
			type: String,
			required: [true, "Name is required"],
		},
		// Unique email address used for admin login
		email: {
			type: String,
			required: [true, "Email is required"],
			unique: true,
			lowercase: true,
			trim: true,
		},
		// Admin's password (expected to be hashed)
		password: {
			type: String,
			required: [true, "Password is required"],
		},
		// Key provided during registration to validate admin eligibility
		adminKey: {
			type: String,
		},
		// Admin role: "Admin", "Super Admin", or "Moderator"
		role: {
			type: String,
			enum: ["Admin", "Super Admin", "Moderator"],
			required: true,
		},
		// Array of permissions assigned to the admin
		permissions: {
			type: [String],
			default: [],
		},
		// Numeric access level between 1 (minimum) and 5 (maximum)
		accessLevel: {
			type: Number,
			min: 1,
			max: 5,
			default: 5,
		},
		// Identifier (ID or email) of the admin who created this account
		adminCreatedBy: {
			type: String,
		},
		// Timestamp when the admin account was created
		adminCreatedOn: {
			type: Date,
			default: Date.now,
		},
		// Timestamp for the last time the admin was active
		lastActive: {
			type: Date,
		},
		// Admin's date of birth
		dateOfBirth: {
			type: Date,
		},
		// Permission flags for various admin capabilities
		canManageUsers: {
			type: Boolean,
			default: false,
		},
		canManageContent: {
			type: Boolean,
			default: false,
		},
		canManagePayments: {
			type: Boolean,
			default: false,
		},
		canViewReports: {
			type: Boolean,
			default: false,
		},
		canApproveNewAdmins: {
			type: Boolean,
			default: false,
		},
		canSuspendUsers: {
			type: Boolean,
			default: false,
		},
		canDeleteData: {
			type: Boolean,
			default: false,
		},
		canExportData: {
			type: Boolean,
			default: false,
		},
		// Super admin key for verifying higher-level privileges
		superAdminKey: {
			type: String,
		},
		// Additional permission flags for managing other admins or security settings
		canPromoteDemoteAdmins: {
			type: Boolean,
			default: false,
		},
		canModifyAdminPermissions: {
			type: Boolean,
			default: false,
		},
		canOverrideSecuritySettings: {
			type: Boolean,
			default: false,
		},
		// Emergency contact for account recovery purposes
		emergencyRecoveryContact: {
			type: String,
		},
		// Email verification properties
		isVerified: {
			type: Boolean,
			default: false,
		},
		emailVerificationToken: {
			type: String,
		},
		emailVerificationExpires: {
			type: Date,
		},
		// Password reset properties
		forgotPasswordToken: {
			type: String,
		},
		forgotPasswordExpires: {
			type: Date,
		},
		// Two-factor authentication properties
		twoFactorEnabled: {
			type: Boolean,
			default: false,
		},
		twoFactorOTP: {
			type: String,
		},
		twoFactorOTPExpires: {
			type: Date,
		},
	},
	{
		// Automatically manage createdAt and updatedAt timestamps and specify collection name
		timestamps: true,
		collection: "admins",
	}
);

// Export the Admin model to be used in controllers and route handlers
export default mongoose.model("Admin", adminSchema);
