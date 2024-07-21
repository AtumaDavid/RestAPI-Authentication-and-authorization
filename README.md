[Technologies/Dependencies](#technologies-dependencies)
[About](#about)

## Technologies/Dependencies

- express
- nedb-promises - A promise-based wrapper for NeDB, a lightweight, in-memory, and file-based database. It provides an easy-to-use API for working with databases in Node.js applications.
- jsonwebtoken
- bcryptjs
- dotenv

### Additional Dependencies for 2FA (Authenticator App)

- qrcode - For generating QR codes
- otplib - For handling Time-based One-Time Passwords (TOTP)
- node-cache - For temporary storage of authentication data

## About

This project implements a robust authentication and authorization system using Node.js and Express. It features user registration, login functionality, role-based access control, and token-based authentication using JSON Web Tokens (JWT). The system utilizes both access tokens and refresh tokens for enhanced security, and now includes Two-Factor Authentication (2FA) for additional account protection.

Key features include:

- User registration with password hashing
- User login with JWT generation
- Two-Factor Authentication (2FA) using authenticator apps
- Role-based access control (e.g., admin, moderator, member)
- Refresh token mechanism for maintaining user sessions
- Secure routes that require authentication
- Database persistence using NeDB

The 2FA implementation allows users to:

- Set up 2FA by scanning a QR code with their authenticator app
- Enable 2FA after verifying the initial setup
- Use 2FA during the login process for enhanced security
