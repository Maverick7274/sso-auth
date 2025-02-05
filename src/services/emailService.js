// src/services/emailService.js

import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();

const transporter = nodemailer.createTransport({
	host: process.env.SMTP_HOST, // e.g. "smtp.gmail.com"
	port: Number(process.env.SMTP_PORT), // e.g. 587
	secure: false, // false for port 587; use true for port 465
	auth: {
		user: process.env.SMTP_USER,
		pass: process.env.SMTP_PASS,
	},
});

export const sendVerificationEmail = async (to, token) => {
	const verificationLink = `http://dayadevraha.com/api/v1/auth/verify-email?token=${token}`;
	const mailOptions = {
		from: `"No Reply" <${process.env.SMTP_USER}>`,
		to,
		subject: "Verify Your Email Address",
		text: `Please verify your email by clicking the following link: ${verificationLink}`,
		html: `<html>
  <head>
    <meta charset="UTF-8">
    <title>Verify Your Email</title>
    <style type="text/css">
      .email-container {
        width: 100%;
        background: #f5f5f5;
        padding: 20px;
        font-family: Arial, sans-serif;
      }
      .email-content {
        max-width: 600px;
        margin: 0 auto;
        background: #ffffff;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      .header {
        background: #007BFF;
        padding: 15px;
        text-align: center;
        color: #ffffff;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
      }
      .body-text {
        color: #333333;
        line-height: 1.5;
      }
      .button {
        display: inline-block;
        margin-top: 20px;
        padding: 12px 20px;
        background: #28a745;
        color: #ffffff;
        text-decoration: none;
        border-radius: 5px;
        font-weight: bold;
      }
      .footer {
        text-align: center;
        margin-top: 20px;
        font-size: 12px;
        color: #999999;
      }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="header">
          <h2>Verify Your Email</h2>
        </div>
        <div class="body-text">
          <p>Hello,</p>
          <p>Thank you for registering with us! Please verify your email address by clicking the button below:</p>
          <p style="text-align:center;">
            <a href="${verificationLink}" class="button">Verify Email</a>
          </p>
          <p>If you cannot click the button, copy and paste the following link into your browser:</p>
          <p style="word-break: break-all;">${verificationLink}</p>
          <p>If you did not sign up, please ignore this email.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 Your Company. All rights reserved.</p>
        </div>
      </div>
    </div>
  </body>
</html>`,
	};
	return transporter.sendMail(mailOptions);
};

export const sendResetPasswordEmail = async (to, token) => {
	const resetLink = `http://dayadevraha.com/api/v1/auth/reset-password?token=${token}`;
	const mailOptions = {
		from: `"No Reply" <${process.env.SMTP_USER}>`,
		to,
		subject: "Reset Your Password",
		text: `You requested a password reset. Click the following link to reset your password: ${resetLink}`,
		html: `<html>
  <head>
    <meta charset="UTF-8">
    <title>Reset Your Password</title>
    <style type="text/css">
      .email-container {
        width: 100%;
        background: #f5f5f5;
        padding: 20px;
        font-family: Arial, sans-serif;
      }
      .email-content {
        max-width: 600px;
        margin: 0 auto;
        background: #ffffff;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      .header {
        background: #dc3545;
        padding: 15px;
        text-align: center;
        color: #ffffff;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
      }
      .body-text {
        color: #333333;
        line-height: 1.5;
      }
      .button {
        display: inline-block;
        margin-top: 20px;
        padding: 12px 20px;
        background: #28a745;
        color: #ffffff;
        text-decoration: none;
        border-radius: 5px;
        font-weight: bold;
      }
      .footer {
        text-align: center;
        margin-top: 20px;
        font-size: 12px;
        color: #999999;
      }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="header">
          <h2>Reset Your Password</h2>
        </div>
        <div class="body-text">
          <p>Hello,</p>
          <p>We received a request to reset your password. Click the button below to set a new password:</p>
          <p style="text-align:center;">
            <a href="${resetLink}" class="button">Reset Password</a>
          </p>
          <p>If you cannot click the button, copy and paste the following link into your browser:</p>
          <p style="word-break: break-all;">${resetLink}</p>
          <p>If you did not request a password reset, please ignore this email.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 Your Company. All rights reserved.</p>
        </div>
      </div>
    </div>
  </body>
</html>`,
	};
	return transporter.sendMail(mailOptions);
};

export const sendTwoFactorOTPEmail = async (to, otp) => {
	const mailOptions = {
		from: `"No Reply" <${process.env.SMTP_USER}>`,
		to,
		subject: "Your Two-Factor Authentication Code",
		text: `Your OTP code is: ${otp}`,
		html: `<html>
  <head>
    <meta charset="UTF-8">
    <title>Your 2FA OTP</title>
    <style type="text/css">
      .email-container {
        width: 100%;
        background: #f5f5f5;
        padding: 20px;
        font-family: Arial, sans-serif;
      }
      .email-content {
        max-width: 600px;
        margin: 0 auto;
        background: #ffffff;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      .header {
        background: #6f42c1;
        padding: 15px;
        text-align: center;
        color: #ffffff;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
      }
      .body-text {
        color: #333333;
        line-height: 1.5;
        text-align: center;
      }
      .otp-code {
        font-size: 32px;
        font-weight: bold;
        color: #dc3545;
        margin: 20px 0;
      }
      .footer {
        text-align: center;
        margin-top: 20px;
        font-size: 12px;
        color: #999999;
      }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="header">
          <h2>Your Two-Factor Authentication Code</h2>
        </div>
        <div class="body-text">
          <p>Hello,</p>
          <p>Your OTP for two-factor authentication is:</p>
          <p class="otp-code">${otp}</p>
          <p>This code is valid for 5 minutes.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 Your Company. All rights reserved.</p>
        </div>
      </div>
    </div>
  </body>
</html>`,
	};
	return transporter.sendMail(mailOptions);
};

export const sendLoginOTPEmail = async (to, otp) => {
	const mailOptions = {
		from: `"No Reply" <${process.env.SMTP_USER}>`,
		to,
		subject: "Your Login OTP Code",
		text: `Your login OTP is: ${otp}`,
		html: `<html>
  <head>
    <meta charset="UTF-8">
    <title>Your Login OTP</title>
    <style type="text/css">
      .email-container {
        width: 100%;
        background: #f5f5f5;
        padding: 20px;
        font-family: Arial, sans-serif;
      }
      .email-content {
        max-width: 600px;
        margin: 0 auto;
        background: #ffffff;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      .header {
        background: #343a40;
        padding: 15px;
        text-align: center;
        color: #ffffff;
        border-top-left-radius: 8px;
        border-top-right-radius: 8px;
      }
      .body-text {
        color: #333333;
        line-height: 1.5;
        text-align: center;
      }
      .otp-code {
        font-size: 32px;
        font-weight: bold;
        color: #28a745;
        margin: 20px 0;
      }
      .footer {
        text-align: center;
        margin-top: 20px;
        font-size: 12px;
        color: #999999;
      }
    </style>
  </head>
  <body>
    <div class="email-container">
      <div class="email-content">
        <div class="header">
          <h2>Your Login OTP Code</h2>
        </div>
        <div class="body-text">
          <p>Hello,</p>
          <p>Your one-time login OTP is:</p>
          <p class="otp-code">${otp}</p>
          <p>This code is valid for 5 minutes.</p>
        </div>
        <div class="footer">
          <p>&copy; 2025 Your Company. All rights reserved.</p>
        </div>
      </div>
    </div>
  </body>
</html>`,
	};
	return transporter.sendMail(mailOptions);
};
