[Technologies/Depedencies](#technologiesdepedencies)
[About](#about)

## Technologies/Depedencies

- express
- nedb-promises = nedb-promises is a promise-based wrapper for NeDB, a lightweight, in-memory, and file-based database. It provides an easy-to-use API for working with databases in Node.js applications.
- jsonwebtoken
- bcryptjs
- dotenv

## technologies for 2FA(for Authenticator app)

- qrcode
- otplib
- node-cache

## About

This project implements a robust authentication and authorization system using Node.js and Express. It features user registration, login functionality, role-based access control, and token-based authentication using JSON Web Tokens (JWT). The system utilizes both access tokens and refresh tokens for enhanced security.

- Key features include:

* User registration with password hashing
* User login with JWT generation
* Role-based access control (e.g., admin, moderator, member)
* Refresh token mechanism for maintaining user sessions
* Secure routes that require authentication
* Database persistence using NeDB
