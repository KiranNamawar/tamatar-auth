# Tamatar Auth - Quick API Flow Reference

## 🚀 Quick API Endpoints Overview

```
📍 BASE URL: http://localhost:3000/auth

🔓 PUBLIC ENDPOINTS (No authentication required)
├── POST /register          → Register new user
├── POST /login             → Login with credentials  
├── POST /verify-email      → Verify email with token
├── POST /resend-verification → Resend verification email
├── POST /forgot-password   → Request password reset
├── POST /reset-password    → Reset password with token
└── POST /refresh           → Refresh access token

🔒 PROTECTED ENDPOINTS (Bearer token required)
├── GET  /me                → Get current user profile
├── POST /logout            → Logout current session
└── POST /logout-all        → Logout all sessions
```

## 🔄 Typical User Flow

```
1. Registration Flow
   Client → POST /register → Email sent → POST /verify-email → Email verified

2. Login Flow  
   Client → POST /login → Returns { user, tokens, session }

3. Access Protected Resources
   Client → GET /me (with Bearer token) → Returns user data

4. Token Refresh
   Client → POST /refresh (with refresh token) → Returns new access token

5. Password Reset
   Client → POST /forgot-password → Email sent → POST /reset-password → Password updated

6. Logout
   Client → POST /logout → Session invalidated
```

## 🛡️ Security Headers

```bash
# Required for protected endpoints
Authorization: Bearer <access_token>

# Content type for POST requests
Content-Type: application/json
```

## 📋 Sample Request/Response Examples

### Registration
```bash
# Request
POST /auth/register
{
  "email": "user@example.com",
  "password": "SecurePass123!",
  "firstName": "John",
  "lastName": "Doe",
  "username": "johndoe"
}

# Response (201)
{
  "success": true,
  "data": {
    "user": {
      "id": "clx...",
      "email": "user@example.com",
      "firstName": "John",
      "emailVerified": false
    }
  },
  "message": "Registration successful. Please check your email for verification."
}
```

### Login
```bash
# Request
POST /auth/login
{
  "email": "user@example.com", 
  "password": "SecurePass123!"
}

# Response (200)
{
  "success": true,
  "data": {
    "user": { "id": "clx...", "email": "user@example.com", ... },
    "tokens": {
      "accessToken": "eyJ...",
      "refreshToken": "eyJ...",
      "expiresIn": 900
    },
    "session": {
      "id": "clx...",
      "expiresAt": "2025-07-07T..."
    }
  }
}
```

### Get Profile
```bash
# Request
GET /auth/me
Authorization: Bearer eyJ...

# Response (200)  
{
  "success": true,
  "data": {
    "user": {
      "id": "clx...",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "emailVerified": true,
      "createdAt": "2025-06-30T..."
    }
  }
}
```

## ⚡ Quick Testing with curl

```bash
# 1. Register a new user
curl -X POST http://localhost:3000/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!",
    "firstName": "Test",
    "username": "testuser"
  }'

# 2. Login (after email verification)
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "TestPass123!"
  }'

# 3. Access protected route (use token from login response)
curl -X GET http://localhost:3000/auth/me \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN_HERE"

# 4. Refresh token
curl -X POST http://localhost:3000/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken": "YOUR_REFRESH_TOKEN_HERE"
  }'
```

## 🎯 Status Codes

| Code | Meaning | Common Scenarios |
|------|---------|------------------|
| 200 | Success | Login, profile access, logout |
| 201 | Created | Registration successful |
| 400 | Bad Request | Invalid input, expired tokens |
| 401 | Unauthorized | Invalid credentials, expired access token |
| 409 | Conflict | User already exists, email not verified |
| 500 | Server Error | Database/server issues |

## 📊 Current Application Status

```
✅ Server Running: http://localhost:3000
✅ API Documentation: http://localhost:3000/swagger  
✅ Database Connected: PostgreSQL
✅ Email Service: Configured (Resend)
✅ All Authentication Flows: Working
✅ No Compilation Errors: Clean codebase
```

Ready to test! 🚀
