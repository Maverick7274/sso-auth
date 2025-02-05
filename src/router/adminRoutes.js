// src/router/adminRoutes.js
import { Router } from "express";
import {
	registerAdmin,
	loginAdmin,
	validateAdminToken,
	logoutAdmin,
	getAdminProfile,
	updateAdminProfile,
	deleteAdminAccount,
} from "../controllers/adminController.js";
import { loginLimiter } from "../middlewares/rateLimiter.js";
import { protect } from "../middlewares/authMiddleware.js";

export default function adminRoutes(version) {
	const router = Router();

	// Public endpoints for admin
	router.post(`/api/v${version}/admin/register`, registerAdmin);
	router.post(`/api/v${version}/admin/login`, loginLimiter, loginAdmin);
	router.get(`/api/v${version}/admin/validate-token`, validateAdminToken);

	// Protected endpoints for admin account operations
	router.use(protect);
	router.post(`/api/v${version}/admin/logout`, logoutAdmin);
	router.get(`/api/v${version}/admin/profile`, getAdminProfile);
	router.put(`/api/v${version}/admin/update-profile`, updateAdminProfile);
	router.delete(`/api/v${version}/admin/delete-account`, deleteAdminAccount);

	return router;
}
