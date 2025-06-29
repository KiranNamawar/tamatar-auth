# API Reference

## Base URL

```
Development: http://localhost:3000
Production: https://auth.tamatar.dev
```

## Authentication

Most endpoints require JWT authentication. Include the token in the Authorization header:

```
Authorization: Bearer <jwt_token>
```

## Response Format

### Success Response
```json
{
  "data": {
    // Response data
  },
  "meta": {
    "timestamp": "2025-06-29T10:30:45.123Z",
    "requestId": "req_1234567890"
  }
}
```

### Error Response
```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "timestamp": "2025-06-29T10:30:45.123Z",
    "path": "/api/endpoint",
    "requestId": "req_1234567890"
  }
}
```

## Core Endpoints

### Health Check

#### GET /health
Check service health status.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2025-06-29T10:30:45.123Z",
  "version": "1.0.50",
  "uptime": 3600,
  "database": "connected",
  "email": "operational"
}
```

---

## Authentication Endpoints

### User Registration

#### POST /register
Register a new user account.

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "username": "johndoe",
  "password": "SecurePassword123!"
}
```

**Validation Rules:**
- `firstName`: Required, 1-50 characters
- `lastName`: Optional, 1-50 characters
- `email`: Required, valid email format, unique
- `username`: Required, 3-30 characters, alphanumeric + underscore, unique
- `password`: Required, minimum 8 characters, must contain uppercase, lowercase, number, and special character

**Response (201):**
```json
{
  "data": {
    "user": {
      "id": "clw1234567890",
      "firstName": "John",
      "lastName": "Doe",
      "email": "john.doe@example.com",
      "username": "johndoe",
      "emailVerified": false,
      "createdAt": "2025-06-29T10:30:45.123Z"
    },
    "message": "Registration successful. Please check your email for verification."
  }
}
```

**Errors:**
- `400` - Validation errors
- `409` - User already exists

---

### User Login

#### POST /login
Authenticate user and receive JWT token.

**Request Body:**
```json
{
  "email": "john.doe@example.com",
  "password": "SecurePassword123!"
}
```

**Optional Headers:**
```
User-Agent: MyApp/1.0.0
X-Forwarded-For: 192.168.1.100
```

**Response (200):**
```json
{
  "data": {
    "user": {
      "id": "clw1234567890",
      "firstName": "John",
      "lastName": "Doe",
      "email": "john.doe@example.com",
      "username": "johndoe",
      "emailVerified": true,
      "avatar": "https://example.com/avatar.jpg"
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": 604800
    },
    "session": {
      "id": "ses_1234567890",
      "expiresAt": "2025-07-06T10:30:45.123Z"
    }
  }
}
```

**Errors:**
- `400` - Validation errors
- `401` - Invalid credentials
- `409` - Email not verified
- `423` - Account locked

---

### User Logout

#### POST /logout
Invalidate current session and optionally all sessions.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body (Optional):**
```json
{
  "allSessions": false
}
```

**Response (200):**
```json
{
  "data": {
    "message": "Logout successful"
  }
}
```

**Errors:**
- `401` - Invalid or missing token

---

### Token Refresh

#### POST /refresh
Refresh access token using refresh token.

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Response (200):**
```json
{
  "data": {
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": 604800
    }
  }
}
```

**Errors:**
- `401` - Invalid or expired refresh token

---

## Email Verification

### Send Verification Email

#### POST /verify-email/send
Send email verification link.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response (200):**
```json
{
  "data": {
    "message": "Verification email sent"
  }
}
```

**Errors:**
- `401` - Authentication required
- `409` - Email already verified
- `429` - Rate limit exceeded

---

### Verify Email

#### POST /verify-email
Verify email address using token.

**Request Body:**
```json
{
  "token": "verification_token_here"
}
```

**Response (200):**
```json
{
  "data": {
    "message": "Email verified successfully",
    "user": {
      "id": "clw1234567890",
      "emailVerified": true
    }
  }
}
```

**Errors:**
- `400` - Invalid or expired token
- `409` - Email already verified

---

## Password Management

### Forgot Password

#### POST /forgot-password
Request password reset email.

**Request Body:**
```json
{
  "email": "john.doe@example.com"
}
```

**Response (200):**
```json
{
  "data": {
    "message": "If an account with this email exists, a password reset link has been sent"
  }
}
```

**Note:** Always returns success to prevent email enumeration.

---

### Reset Password

#### POST /reset-password
Reset password using reset token.

**Request Body:**
```json
{
  "token": "reset_token_here",
  "newPassword": "NewSecurePassword123!"
}
```

**Response (200):**
```json
{
  "data": {
    "message": "Password reset successful"
  }
}
```

**Errors:**
- `400` - Invalid token or weak password
- `410` - Token expired

---

### Change Password

#### POST /change-password
Change password for authenticated user.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "currentPassword": "CurrentPassword123!",
  "newPassword": "NewSecurePassword123!"
}
```

**Response (200):**
```json
{
  "data": {
    "message": "Password changed successfully"
  }
}
```

**Errors:**
- `401` - Authentication required or invalid current password
- `400` - Weak new password

---

## User Profile

### Get Current User

#### GET /me
Get current user profile.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response (200):**
```json
{
  "data": {
    "user": {
      "id": "clw1234567890",
      "firstName": "John",
      "lastName": "Doe",
      "email": "john.doe@example.com",
      "username": "johndoe",
      "avatar": "https://example.com/avatar.jpg",
      "emailVerified": true,
      "createdAt": "2025-06-29T10:30:45.123Z",
      "updatedAt": "2025-06-29T10:30:45.123Z"
    }
  }
}
```

**Errors:**
- `401` - Authentication required

---

### Update Profile

#### PATCH /me
Update current user profile.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Request Body:**
```json
{
  "firstName": "Jane",
  "lastName": "Smith",
  "username": "janesmith"
}
```

**Response (200):**
```json
{
  "data": {
    "user": {
      "id": "clw1234567890",
      "firstName": "Jane",
      "lastName": "Smith",
      "email": "john.doe@example.com",
      "username": "janesmith",
      "avatar": "https://example.com/avatar.jpg",
      "emailVerified": true,
      "updatedAt": "2025-06-29T11:30:45.123Z"
    }
  }
}
```

**Errors:**
- `401` - Authentication required
- `400` - Validation errors
- `409` - Username already taken

---

### Upload Avatar

#### POST /me/avatar
Upload user avatar image.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: multipart/form-data
```

**Request Body:**
```
Form data with 'avatar' file field
```

**Response (200):**
```json
{
  "data": {
    "avatar": "https://cdn.tamatar.dev/avatars/clw1234567890.jpg",
    "message": "Avatar uploaded successfully"
  }
}
```

**Errors:**
- `401` - Authentication required
- `400` - Invalid file format or size
- `413` - File too large

---

## Session Management

### Get Active Sessions

#### GET /sessions
Get all active sessions for current user.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response (200):**
```json
{
  "data": {
    "sessions": [
      {
        "id": "ses_1234567890",
        "userAgent": "Mozilla/5.0...",
        "ipAddress": "192.168.1.100",
        "isValid": true,
        "isCurrent": true,
        "createdAt": "2025-06-29T10:30:45.123Z",
        "expiresAt": "2025-07-06T10:30:45.123Z",
        "lastActivity": "2025-06-29T10:30:45.123Z"
      }
    ]
  }
}
```

**Errors:**
- `401` - Authentication required

---

### Revoke Session

#### DELETE /sessions/:sessionId
Revoke a specific session.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Parameters:**
- `sessionId` (string): Session ID to revoke

**Response (200):**
```json
{
  "data": {
    "message": "Session revoked successfully"
  }
}
```

**Errors:**
- `401` - Authentication required
- `404` - Session not found
- `403` - Cannot revoke session belonging to another user

---

### Revoke All Sessions

#### DELETE /sessions
Revoke all sessions except current.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response (200):**
```json
{
  "data": {
    "message": "All other sessions revoked successfully",
    "revokedCount": 3
  }
}
```

**Errors:**
- `401` - Authentication required

---

## OAuth Integration

### Google OAuth

#### GET /oauth/google
Initiate Google OAuth flow.

**Query Parameters:**
- `redirect_uri` (optional): Custom redirect URI

**Response (302):**
Redirects to Google OAuth consent screen.

---

#### GET /oauth/google/callback
Handle Google OAuth callback.

**Query Parameters:**
- `code`: Authorization code from Google
- `state`: CSRF protection state

**Response (200):**
```json
{
  "data": {
    "user": {
      "id": "clw1234567890",
      "firstName": "John",
      "lastName": "Doe",
      "email": "john.doe@gmail.com",
      "username": "john.doe.gmail",
      "avatar": "https://lh3.googleusercontent.com/...",
      "emailVerified": true,
      "googleId": "google_user_id_123"
    },
    "tokens": {
      "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "expiresIn": 604800
    },
    "isNewUser": false
  }
}
```

**Errors:**
- `400` - Invalid authorization code
- `401` - OAuth authentication failed

---

## Rate Limiting

The API implements rate limiting to prevent abuse:

| Endpoint | Rate Limit | Window |
|----------|------------|--------|
| `/login` | 5 requests | 15 minutes |
| `/register` | 3 requests | 60 minutes |
| `/forgot-password` | 3 requests | 60 minutes |
| `/verify-email/send` | 3 requests | 60 minutes |
| All other endpoints | 100 requests | 15 minutes |

Rate limit headers are included in responses:
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1640995200
```

## CORS Configuration

The API supports CORS for cross-origin requests using the `@elysiajs/cors` plugin:

```typescript
// CORS configuration
import { cors } from '@elysiajs/cors';

const corsPlugin = new Elysia({ name: 'cors' })
  .use(cors({
    origin: process.env.NODE_ENV === 'production' 
      ? ['https://app.tamatar.dev', 'https://admin.tamatar.dev']
      : true, // Allow all origins in development
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Authorization', 'Content-Type', 'X-Requested-With', 'X-CSRF-Token'],
    exposeHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    maxAge: 86400, // 24 hours
  }))
  .as('global');
```

## Error Codes Reference

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `INVALID_EMAIL` | 400 | Invalid email format |
| `WEAK_PASSWORD` | 400 | Password doesn't meet requirements |
| `MISSING_FIELD` | 400 | Required field missing |
| `INVALID_CREDENTIALS` | 401 | Invalid email or password |
| `TOKEN_EXPIRED` | 401 | JWT token has expired |
| `INVALID_TOKEN` | 401 | Invalid or malformed token |
| `MISSING_TOKEN` | 401 | Authentication token required |
| `INSUFFICIENT_PERMISSIONS` | 403 | User lacks required permissions |
| `RESOURCE_ACCESS_DENIED` | 403 | Access to resource denied |
| `USER_NOT_FOUND` | 404 | User not found |
| `SESSION_NOT_FOUND` | 404 | Session not found |
| `USER_ALREADY_EXISTS` | 409 | User with email already exists |
| `EMAIL_NOT_VERIFIED` | 409 | Email verification required |
| `EMAIL_ALREADY_VERIFIED` | 409 | Email already verified |
| `USERNAME_TAKEN` | 409 | Username already taken |
| `ACCOUNT_LOCKED` | 423 | Account temporarily locked |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `EMAIL_SERVICE_ERROR` | 500 | Email service unavailable |
| `DATABASE_ERROR` | 500 | Database operation failed |
| `INTERNAL_SERVER_ERROR` | 500 | Unexpected server error |

## SDKs and Client Libraries

### JavaScript/TypeScript SDK

```typescript
import { TamatarAuth } from '@tamatar/auth-sdk';

const auth = new TamatarAuth({
  baseUrl: 'https://auth.tamatar.dev',
  apiKey: 'your-api-key' // For service-to-service calls
});

// Register user
const user = await auth.register({
  email: 'user@example.com',
  password: 'SecurePassword123!',
  firstName: 'John',
  lastName: 'Doe'
});

// Login
const session = await auth.login({
  email: 'user@example.com',
  password: 'SecurePassword123!'
});

// Get current user
const currentUser = await auth.me();
```

### HTTP Client Examples

#### cURL

```bash
# Register
curl -X POST https://auth.tamatar.dev/register \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "username": "johndoe",
    "password": "SecurePassword123!"
  }'

# Login
curl -X POST https://auth.tamatar.dev/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "SecurePassword123!"
  }'

# Get current user
curl -X GET https://auth.tamatar.dev/me \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Python

```python
import requests

# Base configuration
BASE_URL = "https://auth.tamatar.dev"
headers = {"Content-Type": "application/json"}

# Register
response = requests.post(f"{BASE_URL}/register", 
  headers=headers,
  json={
    "firstName": "John",
    "lastName": "Doe", 
    "email": "john@example.com",
    "username": "johndoe",
    "password": "SecurePassword123!"
  }
)

# Login
response = requests.post(f"{BASE_URL}/login",
  headers=headers, 
  json={
    "email": "john@example.com",
    "password": "SecurePassword123!"
  }
)

token = response.json()["data"]["tokens"]["accessToken"]

# Authenticated request
auth_headers = {**headers, "Authorization": f"Bearer {token}"}
response = requests.get(f"{BASE_URL}/me", headers=auth_headers)
```

## Swagger/OpenAPI Documentation

Interactive API documentation is available at:
- Development: `http://localhost:3000/swagger`
- Production: `https://auth.tamatar.dev/swagger`

The OpenAPI specification can be downloaded at:
- Development: `http://localhost:3000/swagger/json`
- Production: `https://auth.tamatar.dev/swagger/json`
