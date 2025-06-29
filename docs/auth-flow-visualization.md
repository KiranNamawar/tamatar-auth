# Tamatar Auth - Complete Authentication Flow Visualization

This document provides a comprehensive visualization of the authentication flows in the Tamatar Auth microservice.

## 🔐 Complete Authentication Architecture

```mermaid
graph TB
    Client[Client Application]
    API[Tamatar Auth API]
    DB[(PostgreSQL Database)]
    Email[Email Service - Resend]
    JWT[JWT Service]

    Client --> API
    API --> DB
    API --> Email
    API --> JWT
```

## 📋 Database Schema Overview

```mermaid
erDiagram
    User {
        string id PK
        string email UK
        string username UK
        string firstName
        string lastName
        string password
        string googleId UK
        boolean emailVerified
        datetime createdAt
        datetime updatedAt
    }
    
    Session {
        string id PK
        string userId FK
        string userAgent
        string ipAddress
        boolean isValid
        datetime expiresAt
        datetime createdAt
    }
    
    EmailVerificationToken {
        string id PK
        string userId FK
        string token UK
        datetime expiresAt
        datetime createdAt
    }
    
    PasswordResetToken {
        string id PK
        string userId FK
        string token UK
        boolean used
        datetime expiresAt
        datetime createdAt
    }

    User ||--o{ Session : "has many"
    User ||--o{ EmailVerificationToken : "has many"
    User ||--o{ PasswordResetToken : "has many"
```

## 🚀 1. User Registration Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB
    participant Email
    participant User as User's Email

    Client->>API: POST /auth/register
    Note over Client,API: { email, password, firstName, lastName?, username }
    
    API->>DB: Check if user exists
    alt User already exists
        DB-->>API: User found
        API-->>Client: 409 Conflict - User already exists
    else New user
        DB-->>API: User not found
        API->>DB: Create new user (emailVerified: false)
        API->>DB: Create email verification token
        API->>Email: Send verification email
        Email->>User: Verification email with token
        API-->>Client: 201 Created - Registration successful
        Note over Client,API: { user: {...}, message: "Check email for verification" }
    end
```

### Registration Endpoint Details
- **Route**: `POST /auth/register`
- **Validation**: Email format, password strength, required fields
- **Security**: Password hashing with bcrypt
- **Response**: User object (without password) + verification message

## ✉️ 2. Email Verification Flow

```mermaid
sequenceDiagram
    participant User as User's Email
    participant Client
    participant API
    participant DB

    User->>Client: Click verification link
    Client->>API: POST /auth/verify-email
    Note over Client,API: { token: "verification_token" }
    
    API->>DB: Find valid verification token
    alt Token valid and not expired
        DB-->>API: Token found
        API->>DB: Update user.emailVerified = true
        API->>DB: Delete verification token
        API-->>Client: 200 OK - Email verified
    else Token invalid/expired
        DB-->>API: Token not found
        API-->>Client: 400 Bad Request - Invalid token
    end
```

### Email Verification Details
- **Route**: `POST /auth/verify-email`
- **Token Expiry**: 24 hours
- **Security**: One-time use tokens, automatic cleanup

## 🔑 3. User Login Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB
    participant JWT as JWT Service

    Client->>API: POST /auth/login
    Note over Client,API: { email, password }
    
    API->>DB: Find user by email
    alt User not found
        DB-->>API: User not found
        API-->>Client: 401 Unauthorized - Invalid credentials
    else User found
        DB-->>API: User data
        API->>API: Verify password
        alt Password invalid
            API-->>Client: 401 Unauthorized - Invalid credentials
        else Password valid
            alt Email not verified
                API-->>Client: 409 Conflict - Email not verified
            else Email verified
                API->>DB: Create session
                API->>JWT: Generate access & refresh tokens
                JWT-->>API: Token pair
                API->>DB: Update last login
                API-->>Client: 200 OK - Login successful
                Note over Client,API: { user, tokens: { accessToken, refreshToken }, session }
            end
        end
    end
```

### Login Endpoint Details
- **Route**: `POST /auth/login`
- **Tokens**: Access token (15min) + Refresh token (7 days)
- **Session**: Stored in database with expiry
- **Security**: Rate limiting, password verification

## 🔄 4. Token Refresh Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB
    participant JWT as JWT Service

    Client->>API: POST /auth/refresh
    Note over Client,API: { refreshToken }
    
    API->>JWT: Verify refresh token
    alt Token invalid/expired
        JWT-->>API: Invalid token
        API-->>Client: 401 Unauthorized - Invalid refresh token
    else Token valid
        JWT-->>API: Token payload
        API->>DB: Find user and session
        alt User/Session not found
            DB-->>API: Not found
            API-->>Client: 401 Unauthorized - Session invalid
        else Valid session
            DB-->>API: User and session data
            API->>JWT: Generate new access token
            API->>DB: Update session activity
            JWT-->>API: New access token
            API-->>Client: 200 OK - Token refreshed
            Note over Client,API: { accessToken, expiresIn }
        end
    end
```

### Token Refresh Details
- **Route**: `POST /auth/refresh`
- **Purpose**: Get new access token without re-login
- **Security**: Validates refresh token and active session

## 🔐 5. Protected Route Access

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant JWT as JWT Service
    participant DB

    Client->>API: GET /auth/me
    Note over Client,API: Headers: { Authorization: "Bearer <access_token>" }
    
    API->>JWT: Verify access token
    alt Token invalid/expired
        JWT-->>API: Invalid token
        API-->>Client: 401 Unauthorized - Invalid token
    else Token valid
        JWT-->>API: Token payload
        API->>DB: Find user by ID
        alt User not found
            DB-->>API: User not found
            API-->>Client: 404 Not Found - User not found
        else User found
            DB-->>API: User data
            API-->>Client: 200 OK - User profile
            Note over Client,API: { user: {...} }
        end
    end
```

## 🔒 6. Password Reset Flow

```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB
    participant Email
    participant User as User's Email

    Note over Client,API: Step 1: Request Password Reset
    Client->>API: POST /auth/forgot-password
    Note over Client,API: { email }
    
    API->>DB: Find user by email
    API->>DB: Create password reset token
    API->>Email: Send reset email
    Email->>User: Password reset email with token
    API-->>Client: 200 OK - Reset email sent (always success for security)

    Note over Client,API: Step 2: Reset Password
    User->>Client: Click reset link
    Client->>API: POST /auth/reset-password
    Note over Client,API: { token, newPassword }
    
    API->>DB: Find valid reset token
    alt Token valid and not used
        DB-->>API: Token found
        API->>API: Hash new password
        API->>DB: Update user password
        API->>DB: Mark token as used
        API->>DB: Invalidate all user sessions
        API-->>Client: 200 OK - Password reset successful
    else Token invalid/expired/used
        DB-->>API: Token not found/invalid
        API-->>Client: 400 Bad Request - Invalid reset token
    end
```

### Password Reset Details
- **Routes**: 
  - `POST /auth/forgot-password` - Request reset
  - `POST /auth/reset-password` - Complete reset
- **Token Expiry**: 1 hour
- **Security**: One-time use, all sessions invalidated after reset

## 🚪 7. Logout Flows

### Single Device Logout
```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB

    Client->>API: POST /auth/logout
    Note over Client,API: Headers: { Authorization: "Bearer <access_token>" }
    
    API->>API: Verify access token
    API->>DB: Find and invalidate current session
    API-->>Client: 200 OK - Logged out
```

### All Devices Logout
```mermaid
sequenceDiagram
    participant Client
    participant API
    participant DB

    Client->>API: POST /auth/logout-all
    Note over Client,API: Headers: { Authorization: "Bearer <access_token>" }
    
    API->>API: Verify access token
    API->>DB: Invalidate all user sessions
    API-->>Client: 200 OK - Logged out from all devices
```

## 🔄 8. Complete User Journey Example

```mermaid
graph TD
    A[User visits app] --> B[Click Register]
    B --> C[Fill registration form]
    C --> D[Submit - POST /auth/register]
    D --> E[Check email for verification]
    E --> F[Click verification link]
    F --> G[Email verified - POST /auth/verify-email]
    G --> H[Login - POST /auth/login]
    H --> I[Access protected resources]
    
    I --> J{Token expires?}
    J -->|Yes| K[Auto-refresh - POST /auth/refresh]
    K --> I
    J -->|No| I
    
    I --> L[User wants to logout]
    L --> M[POST /auth/logout]
    M --> N[Session invalidated]
    
    I --> O{Forgot password?}
    O -->|Yes| P[POST /auth/forgot-password]
    P --> Q[Check email for reset link]
    Q --> R[POST /auth/reset-password]
    R --> S[All sessions invalidated]
    S --> H
```

## 🛡️ Security Features

### 1. **Token Security**
- Access tokens: Short-lived (15 minutes)
- Refresh tokens: Longer-lived (7 days)
- JWT signing with secure secrets
- Token rotation on refresh

### 2. **Session Management**
- Database-stored sessions
- Session invalidation on logout
- Automatic cleanup of expired sessions
- IP address and user agent tracking

### 3. **Password Security**
- bcrypt hashing with salt rounds
- Password strength validation
- Secure password reset flow
- All sessions invalidated on password change

### 4. **Email Security**
- Time-limited verification tokens
- One-time use tokens
- Automatic token cleanup
- Secure reset flow (no user enumeration)

### 5. **Rate Limiting** (Configurable)
- Login attempt limiting
- Registration rate limiting
- Password reset rate limiting

## 📱 API Endpoints Summary

| Endpoint | Method | Purpose | Auth Required |
|----------|--------|---------|---------------|
| `/auth/register` | POST | User registration | ❌ |
| `/auth/login` | POST | User login | ❌ |
| `/auth/verify-email` | POST | Email verification | ❌ |
| `/auth/resend-verification` | POST | Resend verification email | ❌ |
| `/auth/forgot-password` | POST | Request password reset | ❌ |
| `/auth/reset-password` | POST | Complete password reset | ❌ |
| `/auth/refresh` | POST | Refresh access token | ❌ |
| `/auth/me` | GET | Get user profile | ✅ |
| `/auth/logout` | POST | Logout current session | ✅ |
| `/auth/logout-all` | POST | Logout all sessions | ✅ |

## 🎯 Key Features

✅ **Complete Authentication System**  
✅ **Email Verification**  
✅ **Password Reset**  
✅ **JWT Token Management**  
✅ **Session Management**  
✅ **Security Best Practices**  
✅ **Rate Limiting Ready**  
✅ **OAuth Ready** (extensible)  

The Tamatar Auth system provides a complete, secure, and production-ready authentication solution with all modern security practices implemented.
