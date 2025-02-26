/*
File: /src/utils/logger.js
Description: Logger utility using winston for application logging. This logger sends output to both the console and a log file.
*/

import { createLogger, format, transports } from "winston";

// Create a logger instance with a specific logging format and transports.
// Logging level: "info" by default; timestamps are added to each log entry.
const logger = createLogger({
	level: "info",
	format: format.combine(
		format.timestamp(), // Append a timestamp to each log message.
		format.printf(({ timestamp, level, message }) =>
			// Custom log format: "timestamp [level]: message".
			`${timestamp} [${level}]: ${message}`
		)
	),
	transports: [
		new transports.Console(), // Log output to the console.
		new transports.File({ filename: "logs/app.log" }), // Log output to a file.
	],
});

export default logger;
