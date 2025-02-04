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
import { loginLimiter } from "../middlewares/rateLimiter.js";
import { protect } from "../middlewares/authMiddleware.js";

export default function userRoutes(version) {
	const router = Router();

	// Authentication endpoints
	router.post(`/api/v${version}/auth/register`, registerUser);
	router.post(`/api/v${version}/auth/login`, loginLimiter, loginUser);
	router.get(`/api/v${version}/auth/validate-token`, validateUserToken);
	router.post(`/api/v${version}/auth/logout`, logoutUser);

	// CRUD endpoints for user profile
	router.get(`/api/v${version}/auth/profile`, protect, getUserProfile);
	router.put(
		`/api/v${version}/auth/update-profile`,
		protect,
		updateUserProfile
	);
	router.delete(
		`/api/v${version}/auth/delete-account`,
		protect,
		deleteUserAccount
	);

	return router;
}
