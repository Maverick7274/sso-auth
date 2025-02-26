/**
 * helpers.js
 *
 * This file contains helper functions for the SSO Authentication Server.
 * These functions are used in various route handlers (e.g., /api/auth/login) to
 * send standardized responses and to format error messages.
 */

/**
 * Sends a standardized JSON response.
 *
 * @param {Object} res - Express response object.
 * @param {number} statusCode - HTTP status code.
 * @param {boolean} success - Indicates if the request succeeded.
 * @param {any} [data=null] - Payload data to send.
 * @param {string} [message=""] - Optional message to include.
 * @returns {Object} JSON response.
 */
export const sendResponse = (
	res,
	statusCode,
	success,
	data = null,
	message = ""
) => {
	return res.status(statusCode).json({ success, data, message });
};

/**
 * Formats an array of error objects into a standardized structure.
 *
 * @param {Array} errors - Array of error objects (each should have 'path' and 'message' properties).
 * @returns {Array} Array of formatted error objects with 'field' and 'message'.
 */
export const formatError = (errors) => {
	return errors.map((err) => ({ field: err.path, message: err.message }));
};
