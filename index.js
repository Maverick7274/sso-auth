// Import the main Express application, environment configuration, and database connection function
import app from './src/app.js'
import dotenv from 'dotenv';
import connectDB from './src/config/db.js';

// Load environment variables from the .env file
dotenv.config();

// Define the server port from environment variables or default to 6000
const SERVER_PORT = process.env.SERVER_PORT || 6000;

/*
    Handle uncaught exceptions:
    These are synchronous errors that were not caught anywhere.
    The server is shut down immediately to avoid any unpredictable behavior.
*/
process.on("uncaughtException", err => {
        console.error(`Uncaught Exception: ${err.message}`);
        console.error("Shutting down the server due to an uncaught exception");
        process.exit(1);
});

// Connect to the database before starting the server
connectDB();

/*
    Start the Express server:
    The routes (API endpoints) are defined in the imported app module (typically in src/app.js).
    The server listens on the defined port and logs the URL.
*/
const server = app.listen(SERVER_PORT, () => {
        console.log(`Server is running on http://localhost:${SERVER_PORT}/`);
});

/*
    Handle unhandled promise rejections:
    If any promise is rejected and not caught anywhere in the application,
    the server is gracefully shut down after finishing any active requests.
*/
process.on("unhandledRejection", err => {
        console.error(`Unhandled Rejection: ${err.message}`);
        console.error("Shutting down the server due to an unhandled promise rejection");

        server.close(() => {
                process.exit(1);
        });
});