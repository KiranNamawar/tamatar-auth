# Project Overview

Tamatar Auth is a centralized authentication microservice for the Tamatar ecosystem, built with:
- **Runtime**: Bun (JavaScript runtime)
- **Framework**: Elysia.js (TypeScript web framework)
- **Database**: PostgreSQL with Prisma ORM
- **Authentication**: JWT tokens with session management
- **Email**: Resend with React Email templates
- **Validation**: TypeBox with Elysia
- **Testing**: Bun test framework
- **Code Quality**: Biome for linting and formatting

## Architecture Patterns

### Authentication Flow
- JWT-based authentication with refresh tokens
- Session management with database persistence
- Email verification for new accounts
- Password reset functionality with secure tokens
- OAuth integration (Google, extensible for others)

### Error Handling
- Custom error classes with specific error codes
- Centralized error handling middleware
- Structured error responses with proper HTTP status codes
- Comprehensive error logging and monitoring

### Database Design
- User management with profiles
- Session tracking and management
- Email verification tokens
- Password reset tokens
- Audit logging for security events

## File Structure Context

```
src/
├── index.ts              # Main application entry point
├── routes/               # API route handlers
│   ├── auth.ts          # Authentication endpoints
│   ├── users.ts         # User management endpoints
│   └── health.ts        # Health check endpoints
├── middleware/           # Custom middleware
│   ├── auth.ts          # Authentication middleware
│   ├── cors.ts          # CORS configuration
│   ├── rate-limit.ts    # Rate limiting
│   └── error.ts         # Error handling
├── lib/                 # Utility libraries
│   ├── db/              # Database operations
│   ├── email/           # Email service
│   ├── auth/            # Authentication utilities
│   ├── validation/      # Input validation
│   └── utils/           # General utilities
├── types/               # TypeScript definitions
└── generated/           # Generated code (ignored in git)
```
