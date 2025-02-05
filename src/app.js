// src/app.js
import express from "express";
import cors from "cors";
import helmet from "helmet";
import cookieParser from "cookie-parser";
import morgan from "morgan";
import dotenv from "dotenv";
import userRoutes from "./router/userRoutes.js";
import adminRoutes from "./router/adminRoutes.js";
import userExtraRoutes from "./router/userExtraRoutes.js";

dotenv.config();

const app = express();
const CLIENT_PORT = process.env.CLIENT_PORT || 8000;
const API_VERSION = process.env.VERSION || "1";

app.use(helmet());
app.use(morgan("combined"));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(
	cors({
		origin: `http://localhost:${CLIENT_PORT}`,
		optionsSuccessStatus: 200,
	})
);

// Mount routers using the factory functions
app.use(userRoutes(API_VERSION));
app.use(adminRoutes(API_VERSION));
app.use(userExtraRoutes(API_VERSION));

app.get("/", (req, res) => {
	res.send("Welcome to the Authentication API");
});

// 404 Handler
app.use((req, res, next) => {
	res.status(404).json({ success: false, message: "Route not found" });
});

// Global Error Handler
app.use((err, req, res, next) => {
	console.error(err.stack);
	res.status(500).json({ success: false, message: "Internal Server Error" });
});

export default app;
