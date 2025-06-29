# Error Handling Best Practices

## Overview

Robust error handling is crucial for a reliable authentication microservice. This guide outlines the error handling patterns, custom error classes, and best practices implemented in Tamatar Auth.

## Error Categories

### 1. Authentication Errors
- Invalid credentials
- Expired tokens
- Missing authentication headers
- Invalid token format

### 2. Authorization Errors
- Insufficient permissions
- Resource access denied
- Invalid session

### 3. Validation Errors
- Invalid input data
- Missing required fields
- Data format violations

### 4. Business Logic Errors
- User already exists
- Email not verified
- Account locked/suspended

### 5. System Errors
- Database connection failures
- Email service unavailable
- Internal server errors

## Error Response Format

All API errors follow a consistent format:

```typescript
interface ErrorResponse {
  error: {
    code: string;           // Machine-readable error code
    message: string;        // Human-readable error message
    details?: any;          // Additional error context
    timestamp: string;      // ISO timestamp
    path: string;          // Request path
    requestId?: string;    // Unique request identifier
  }
}
```

### Example Error Response

```json
{
  "error": {
    "code": "INVALID_CREDENTIALS",
    "message": "Invalid email or password",
    "timestamp": "2025-06-29T10:30:45.123Z",
    "path": "/login",
    "requestId": "req_1234567890"
  }
}
```

## Custom Error Classes

### Base Error Class

```typescript
// src/lib/errors/base.ts
export abstract class BaseError extends Error {
  abstract readonly code: string;
  abstract readonly statusCode: number;
  readonly timestamp: string;
  readonly details?: any;

  constructor(message: string, details?: any) {
    super(message);
    this.name = this.constructor.name;
    this.timestamp = new Date().toISOString();
    this.details = details;
    
    // Maintain proper stack trace
    Error.captureStackTrace(this, this.constructor);
  }

  toJSON() {
    return {
      code: this.code,
      message: this.message,
      timestamp: this.timestamp,
      details: this.details,
    };
  }
}
```

### Authentication Errors

```typescript
// src/lib/errors/auth.ts
export class AuthenticationError extends BaseError {
  readonly code = 'AUTHENTICATION_ERROR';
  readonly statusCode = 401;
}

export class InvalidCredentialsError extends AuthenticationError {
  readonly code = 'INVALID_CREDENTIALS';
  
  constructor() {
    super('Invalid email or password');
  }
}

export class TokenExpiredError extends AuthenticationError {
  readonly code = 'TOKEN_EXPIRED';
  
  constructor() {
    super('Authentication token has expired');
  }
}

export class InvalidTokenError extends AuthenticationError {
  readonly code = 'INVALID_TOKEN';
  
  constructor() {
    super('Invalid or malformed authentication token');
  }
}

export class MissingTokenError extends AuthenticationError {
  readonly code = 'MISSING_TOKEN';
  
  constructor() {
    super('Authentication token is required');
  }
}
```

### Authorization Errors

```typescript
// src/lib/errors/authorization.ts
export class AuthorizationError extends BaseError {
  readonly code = 'AUTHORIZATION_ERROR';
  readonly statusCode = 403;
}

export class InsufficientPermissionsError extends AuthorizationError {
  readonly code = 'INSUFFICIENT_PERMISSIONS';
  
  constructor(permission: string) {
    super(`Insufficient permissions: ${permission} required`);
  }
}

export class ResourceAccessDeniedError extends AuthorizationError {
  readonly code = 'RESOURCE_ACCESS_DENIED';
  
  constructor(resource: string) {
    super(`Access denied to resource: ${resource}`);
  }
}
```

### Validation Errors

```typescript
// src/lib/errors/validation.ts
export class ValidationError extends BaseError {
  readonly code = 'VALIDATION_ERROR';
  readonly statusCode = 400;
}

export class InvalidEmailError extends ValidationError {
  readonly code = 'INVALID_EMAIL';
  
  constructor() {
    super('Please provide a valid email address');
  }
}

export class WeakPasswordError extends ValidationError {
  readonly code = 'WEAK_PASSWORD';
  
  constructor() {
    super('Password must be at least 8 characters with uppercase, lowercase, number, and special character');
  }
}

export class MissingFieldError extends ValidationError {
  readonly code = 'MISSING_FIELD';
  
  constructor(field: string) {
    super(`Required field missing: ${field}`);
  }
}
```

### Business Logic Errors

```typescript
// src/lib/errors/business.ts
export class BusinessLogicError extends BaseError {
  readonly code = 'BUSINESS_LOGIC_ERROR';
  readonly statusCode = 409;
}

export class UserAlreadyExistsError extends BusinessLogicError {
  readonly code = 'USER_ALREADY_EXISTS';
  
  constructor() {
    super('An account with this email already exists');
  }
}

export class EmailNotVerifiedError extends BusinessLogicError {
  readonly code = 'EMAIL_NOT_VERIFIED';
  
  constructor() {
    super('Please verify your email address to continue');
  }
}

export class AccountLockedError extends BusinessLogicError {
  readonly code = 'ACCOUNT_LOCKED';
  
  constructor() {
    super('Account has been temporarily locked due to multiple failed login attempts');
  }
}
```

### System Errors

```typescript
// src/lib/errors/system.ts
export class SystemError extends BaseError {
  readonly code = 'SYSTEM_ERROR';
  readonly statusCode = 500;
}

export class DatabaseError extends SystemError {
  readonly code = 'DATABASE_ERROR';
  
  constructor(operation: string) {
    super(`Database operation failed: ${operation}`);
  }
}

export class EmailServiceError extends SystemError {
  readonly code = 'EMAIL_SERVICE_ERROR';
  
  constructor() {
    super('Email service is temporarily unavailable');
  }
}

export class ExternalServiceError extends SystemError {
  readonly code = 'EXTERNAL_SERVICE_ERROR';
  
  constructor(service: string) {
    super(`External service unavailable: ${service}`);
  }
}
```

## Error Handler Middleware

```typescript
// src/lib/middleware/error-handler.ts
import type { Context } from 'elysia';
import { BaseError } from '../errors/base';
import { logger } from '../utils/logger';

export const errorHandler = (error: Error, ctx: Context) => {
  const requestId = ctx.headers['x-request-id'] || generateRequestId();
  
  // Log error with context
  logger.error('Request failed', {
    error: error.message,
    stack: error.stack,
    requestId,
    path: ctx.path,
    method: ctx.request.method,
    userAgent: ctx.headers['user-agent'],
    ip: ctx.headers['x-forwarded-for'] || ctx.request.headers.get('x-real-ip'),
  });

  // Handle custom errors
  if (error instanceof BaseError) {
    return ctx
      .set.status(error.statusCode)
      .json({
        error: {
          ...error.toJSON(),
          path: ctx.path,
          requestId,
        },
      });
  }

  // Handle Prisma errors
  if (error.name === 'PrismaClientKnownRequestError') {
    return handlePrismaError(error, ctx, requestId);
  }

  // Handle validation errors (from Elysia/TypeBox)
  if (error.name === 'ValidationError') {
    return ctx
      .set.status(400)
      .json({
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid request data',
          details: error.message,
          timestamp: new Date().toISOString(),
          path: ctx.path,
          requestId,
        },
      });
  }

  // Handle unexpected errors
  return ctx
    .set.status(500)
    .json({
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected error occurred',
        timestamp: new Date().toISOString(),
        path: ctx.path,
        requestId,
      },
    });
};

function handlePrismaError(error: any, ctx: Context, requestId: string) {
  const { code } = error;
  
  switch (code) {
    case 'P2002': // Unique constraint violation
      return ctx
        .set.status(409)
        .json({
          error: {
            code: 'DUPLICATE_ENTRY',
            message: 'A record with this information already exists',
            timestamp: new Date().toISOString(),
            path: ctx.path,
            requestId,
          },
        });
    
    case 'P2025': // Record not found
      return ctx
        .set.status(404)
        .json({
          error: {
            code: 'RECORD_NOT_FOUND',
            message: 'The requested resource was not found',
            timestamp: new Date().toISOString(),
            path: ctx.path,
            requestId,
          },
        });
    
    default:
      return ctx
        .set.status(500)
        .json({
          error: {
            code: 'DATABASE_ERROR',
            message: 'A database error occurred',
            timestamp: new Date().toISOString(),
            path: ctx.path,
            requestId,
          },
        });
  }
}

function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}
```

## Usage Examples

### In Route Handlers

```typescript
// src/routes/auth.ts
import { Elysia } from 'elysia';
import { 
  InvalidCredentialsError, 
  UserAlreadyExistsError,
  EmailNotVerifiedError 
} from '../lib/errors';

export const authRoutes = new Elysia({ prefix: '/auth' })
  .post('/login', async ({ body }) => {
    const { email, password } = body;
    
    const user = await prisma.user.findUnique({
      where: { email }
    });
    
    if (!user || !await bcrypt.compare(password, user.password)) {
      throw new InvalidCredentialsError();
    }
    
    if (!user.emailVerified) {
      throw new EmailNotVerifiedError();
    }
    
    // Generate JWT and return success response
    // ...
  })
  .post('/register', async ({ body }) => {
    const { email, password, firstName } = body;
    
    const existingUser = await prisma.user.findUnique({
      where: { email }
    });
    
    if (existingUser) {
      throw new UserAlreadyExistsError();
    }
    
    // Create user and return success response
    // ...
  });
```

### With Database Operations

```typescript
// src/lib/db/user.ts
import { DatabaseError } from '../errors';

export async function createUser(data: CreateUserData) {
  try {
    return await prisma.user.create({
      data,
    });
  } catch (error) {
    logger.error('Failed to create user', { error, data });
    throw new DatabaseError('user creation');
  }
}

export async function getUserById(id: string) {
  try {
    const user = await prisma.user.findUnique({
      where: { id },
    });
    
    if (!user) {
      throw new RecordNotFoundError('user');
    }
    
    return user;
  } catch (error) {
    if (error instanceof BaseError) {
      throw error;
    }
    
    logger.error('Failed to get user', { error, id });
    throw new DatabaseError('user retrieval');
  }
}
```

### With External Services

```typescript
// src/lib/email/service.ts
import { EmailServiceError } from '../errors';

export async function sendVerificationEmail(email: string, token: string) {
  try {
    await resend.emails.send({
      from: 'auth@email.tamatar.dev',
      to: email,
      subject: 'Verify your email',
      react: VerificationEmailTemplate({ token }),
    });
  } catch (error) {
    logger.error('Failed to send verification email', { error, email });
    throw new EmailServiceError();
  }
}
```

## Error Monitoring and Alerting

### Integration with Logging Services

```typescript
// src/lib/utils/logger.ts
import { createLogger, format, transports } from 'winston';

export const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.json()
  ),
  transports: [
    new transports.Console(),
    new transports.File({ filename: 'logs/error.log', level: 'error' }),
    new transports.File({ filename: 'logs/combined.log' }),
  ],
});

// Add Sentry or other error tracking service
if (process.env.SENTRY_DSN) {
  // Configure Sentry
}
```

### Metrics Collection

```typescript
// src/lib/middleware/metrics.ts
export const metricsMiddleware = (app: Elysia) => {
  return app.onError((error, ctx) => {
    // Increment error counters
    metrics.increment('errors.total', {
      error_type: error.constructor.name,
      status_code: ctx.response?.status || 500,
      path: ctx.path,
    });
  });
};
```

## Testing Error Scenarios

### Unit Tests

```typescript
// tests/errors/auth.test.ts
import { describe, it, expect } from 'bun:test';
import { InvalidCredentialsError } from '../../src/lib/errors';

describe('Authentication Errors', () => {
  it('should create InvalidCredentialsError with correct properties', () => {
    const error = new InvalidCredentialsError();
    
    expect(error.code).toBe('INVALID_CREDENTIALS');
    expect(error.statusCode).toBe(401);
    expect(error.message).toBe('Invalid email or password');
    expect(error.timestamp).toBeDefined();
  });
  
  it('should serialize to JSON correctly', () => {
    const error = new InvalidCredentialsError();
    const json = error.toJSON();
    
    expect(json).toEqual({
      code: 'INVALID_CREDENTIALS',
      message: 'Invalid email or password',
      timestamp: expect.any(String),
    });
  });
});
```

### Integration Tests

```typescript
// tests/integration/auth.test.ts
import { describe, it, expect } from 'bun:test';
import { app } from '../../src/index';

describe('Authentication API', () => {
  it('should return 401 for invalid credentials', async () => {
    const response = await app.handle(
      new Request('http://localhost/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: 'invalid@example.com',
          password: 'wrongpassword',
        }),
      })
    );
    
    expect(response.status).toBe(401);
    
    const body = await response.json();
    expect(body.error.code).toBe('INVALID_CREDENTIALS');
  });
});
```

## Best Practices

### 1. Consistent Error Codes
- Use machine-readable error codes
- Follow a consistent naming convention
- Document all error codes

### 2. Meaningful Messages
- Provide clear, actionable error messages
- Avoid exposing sensitive information
- Use user-friendly language

### 3. Proper HTTP Status Codes
- Use appropriate HTTP status codes
- Be consistent across similar error types
- Follow REST conventions

### 4. Error Context
- Include relevant context (timestamp, request ID)
- Log errors with sufficient detail
- Track error patterns and frequencies

### 5. Security Considerations
- Don't expose internal implementation details
- Avoid information leakage through errors
- Rate limit error responses to prevent abuse

### 6. Error Recovery
- Provide guidance on how to resolve errors
- Suggest alternative actions when possible
- Include links to documentation

### 7. Monitoring and Alerting
- Set up alerts for critical error rates
- Monitor error trends and patterns
- Track error resolution times

## Error Code Reference

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `INVALID_CREDENTIALS` | 401 | Invalid email or password |
| `TOKEN_EXPIRED` | 401 | JWT token has expired |
| `INVALID_TOKEN` | 401 | Invalid or malformed token |
| `MISSING_TOKEN` | 401 | Authentication token required |
| `INSUFFICIENT_PERMISSIONS` | 403 | User lacks required permissions |
| `RESOURCE_ACCESS_DENIED` | 403 | Access to resource denied |
| `VALIDATION_ERROR` | 400 | Request validation failed |
| `MISSING_FIELD` | 400 | Required field missing |
| `INVALID_EMAIL` | 400 | Invalid email format |
| `WEAK_PASSWORD` | 400 | Password doesn't meet requirements |
| `USER_ALREADY_EXISTS` | 409 | User with email already exists |
| `EMAIL_NOT_VERIFIED` | 409 | Email verification required |
| `ACCOUNT_LOCKED` | 409 | Account temporarily locked |
| `DATABASE_ERROR` | 500 | Database operation failed |
| `EMAIL_SERVICE_ERROR` | 500 | Email service unavailable |
| `INTERNAL_SERVER_ERROR` | 500 | Unexpected server error |

This comprehensive error handling system ensures that all errors are handled consistently, providing clear feedback to clients while maintaining security and enabling effective debugging and monitoring.
