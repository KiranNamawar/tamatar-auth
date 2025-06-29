# Error Handling Patterns

This guide covers error handling best practices for the Tamatar Auth project using Elysia.js patterns and centralized error management.

## Custom Error Classes

### Base Error Infrastructure

```typescript
// Base error class for all application errors
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

### Validation Errors

```typescript
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
  readonly statusCode = 423;
  
  constructor() {
    super('Account has been temporarily locked due to multiple failed login attempts');
  }
}
```

## Elysia.js Error Handling

### Centralized Error Handler

```typescript
import { Elysia } from 'elysia';
import { BaseError } from '../errors/base';
import { logger } from '../utils/logger';

export const errorHandler = new Elysia({ name: 'error-handler' })
  .onError(({ error, set, request, code }) => {
    const requestId = request.headers.get('x-request-id') || generateRequestId();
    
    // Log error with context
    logger.error('Request failed', {
      error: error.message,
      stack: error.stack,
      requestId,
      path: new URL(request.url).pathname,
      method: request.method,
      userAgent: request.headers.get('user-agent'),
      ip: request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip'),
      code
    });

    // Set common response headers
    set.headers = {
      'Content-Type': 'application/json',
      'X-Request-ID': requestId
    };

    // Handle custom errors
    if (error instanceof BaseError) {
      set.status = error.statusCode;
      return {
        error: {
          ...error.toJSON(),
          path: new URL(request.url).pathname,
          requestId,
        },
      };
    }

    // Handle Elysia validation errors
    if (code === 'VALIDATION') {
      set.status = 400;
      return {
        error: {
          code: 'VALIDATION_ERROR',
          message: 'Invalid request data',
          details: error.message,
          timestamp: new Date().toISOString(),
          path: new URL(request.url).pathname,
          requestId,
        },
      };
    }

    // Handle Prisma errors
    if (error.name === 'PrismaClientKnownRequestError') {
      return handlePrismaError(error, set, request, requestId);
    }

    // Handle unexpected errors
    set.status = 500;
    return {
      error: {
        code: 'INTERNAL_SERVER_ERROR',
        message: 'An unexpected error occurred',
        timestamp: new Date().toISOString(),
        path: new URL(request.url).pathname,
        requestId,
      },
    };
  })
  .as('global');

function handlePrismaError(error: any, set: any, request: Request, requestId: string) {
  const { code } = error;
  
  switch (code) {
    case 'P2002': // Unique constraint violation
      set.status = 409;
      return {
        error: {
          code: 'DUPLICATE_ENTRY',
          message: 'A record with this information already exists',
          timestamp: new Date().toISOString(),
          path: new URL(request.url).pathname,
          requestId,
        },
      };
    
    case 'P2025': // Record not found
      set.status = 404;
      return {
        error: {
          code: 'RECORD_NOT_FOUND',
          message: 'The requested resource was not found',
          timestamp: new Date().toISOString(),
          path: new URL(request.url).pathname,
          requestId,
        },
      };
    
    default:
      set.status = 500;
      return {
        error: {
          code: 'DATABASE_ERROR',
          message: 'A database error occurred',
          timestamp: new Date().toISOString(),
          path: new URL(request.url).pathname,
          requestId,
        },
      };
  }
}

function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
}
```

### Route-Level Error Handling

```typescript
// Authentication routes with specific error handling
export const authRoutes = new Elysia({ prefix: '/auth' })
  .use(errorHandler)
  .post('/login', async ({ body, set }) => {
    try {
      const { email, password } = body;
      
      const user = await getUserByEmail(email);
      if (!user) {
        throw new InvalidCredentialsError();
      }
      
      const isValidPassword = await verifyPassword(password, user.password);
      if (!isValidPassword) {
        throw new InvalidCredentialsError();
      }
      
      if (!user.emailVerified) {
        throw new EmailNotVerifiedError();
      }
      
      const tokens = await generateTokens(user);
      return { user: sanitizeUser(user), tokens };
      
    } catch (error) {
      // Let the global error handler deal with it
      throw error;
    }
  }, {
    body: t.Object({
      email: t.String({ format: 'email' }),
      password: t.String()
    })
  })
  .post('/register', async ({ body }) => {
    try {
      const existingUser = await getUserByEmail(body.email);
      if (existingUser) {
        throw new UserAlreadyExistsError();
      }
      
      const user = await createUser(body);
      await sendVerificationEmail(user);
      
      return { 
        user: sanitizeUser(user),
        message: 'Registration successful. Please check your email for verification.'
      };
      
    } catch (error) {
      throw error;
    }
  }, {
    body: t.Object({
      email: t.String({ format: 'email' }),
      password: t.String({ minLength: 8 }),
      firstName: t.String({ minLength: 1 }),
      lastName: t.Optional(t.String())
    })
  });
```

### Async Error Handling

```typescript
// Service layer with proper async error handling
export class UserService {
  async createUser(userData: UserCreateRequest): Promise<User> {
    try {
      // Validate password strength
      if (!isPasswordStrong(userData.password)) {
        throw new WeakPasswordError();
      }
      
      // Hash password
      const hashedPassword = await hashPassword(userData.password);
      
      // Create user in transaction
      const user = await db.$transaction(async (tx) => {
        const newUser = await tx.user.create({
          data: {
            ...userData,
            password: hashedPassword,
          },
        });
        
        // Create user profile
        await tx.userProfile.create({
          data: {
            userId: newUser.id,
            firstName: userData.firstName,
            lastName: userData.lastName,
          },
        });
        
        return newUser;
      });
      
      return user;
      
    } catch (error) {
      if (error instanceof BaseError) {
        throw error;
      }
      
      // Handle Prisma errors
      if (error.code === 'P2002') {
        throw new UserAlreadyExistsError();
      }
      
      logger.error('User creation failed', { error, userData });
      throw new Error('Failed to create user');
    }
  }
  
  async authenticateUser(email: string, password: string): Promise<User> {
    try {
      const user = await getUserByEmail(email);
      if (!user) {
        throw new InvalidCredentialsError();
      }
      
      const isValid = await verifyPassword(password, user.password);
      if (!isValid) {
        // Log failed login attempt
        await logLoginAttempt(email, false);
        throw new InvalidCredentialsError();
      }
      
      if (!user.emailVerified) {
        throw new EmailNotVerifiedError();
      }
      
      // Check if account is locked
      const isLocked = await isAccountLocked(user.id);
      if (isLocked) {
        throw new AccountLockedError();
      }
      
      // Log successful login
      await logLoginAttempt(email, true);
      await updateLastLogin(user.id);
      
      return user;
      
    } catch (error) {
      if (error instanceof BaseError) {
        throw error;
      }
      
      logger.error('Authentication failed', { error, email });
      throw new Error('Authentication failed');
    }
  }
}
```

## Error Response Format

### Standardized Error Responses

```typescript
// Error response interface
export interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: any;
    timestamp: string;
    path: string;
    requestId?: string;
  };
}

// Success response wrapper
export interface SuccessResponse<T> {
  data: T;
  meta?: {
    timestamp: string;
    requestId: string;
  };
}

// Helper functions for consistent responses
export function createErrorResponse(
  error: BaseError,
  path: string,
  requestId?: string
): ErrorResponse {
  return {
    error: {
      code: error.code,
      message: error.message,
      details: error.details,
      timestamp: error.timestamp,
      path,
      requestId,
    },
  };
}

export function createSuccessResponse<T>(
  data: T,
  requestId?: string
): SuccessResponse<T> {
  return {
    data,
    meta: {
      timestamp: new Date().toISOString(),
      requestId: requestId || generateRequestId(),
    },
  };
}
```

## Validation Error Handling

### TypeBox Validation with Custom Errors

```typescript
import { t, Value, ValueError } from '@sinclair/typebox';

// Custom validation with detailed error messages
export function validateAndTransform<T>(schema: any, data: unknown): T {
  try {
    // Validate using TypeBox
    if (!Value.Check(schema, data)) {
      const errors = [...Value.Errors(schema, data)];
      
      const validationErrors = errors.map((error: ValueError) => ({
        field: error.path.replace(/^\//, ''), // Remove leading slash
        message: getValidationMessage(error),
        received: error.value,
        expected: error.schema,
      }));
      
      throw new ValidationError('Request validation failed', validationErrors);
    }
    
    // Transform and return validated data
    return Value.Convert(schema, data) as T;
    
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }
    
    throw new ValidationError('Invalid request data');
  }
}

function getValidationMessage(error: ValueError): string {
  switch (error.type) {
    case 'string':
      if (error.schema.format === 'email') {
        return 'Must be a valid email address';
      }
      if (error.schema.minLength) {
        return `Must be at least ${error.schema.minLength} characters`;
      }
      if (error.schema.maxLength) {
        return `Must be no more than ${error.schema.maxLength} characters`;
      }
      return 'Must be a string';
      
    case 'number':
      if (error.schema.minimum) {
        return `Must be at least ${error.schema.minimum}`;
      }
      if (error.schema.maximum) {
        return `Must be no more than ${error.schema.maximum}`;
      }
      return 'Must be a number';
      
    case 'required':
      return 'This field is required';
      
    default:
      return error.message || 'Invalid value';
  }
}

// Use in Elysia routes
export const userRoutes = new Elysia({ prefix: '/users' })
  .use(errorHandler)
  .derive(({ body, query, params }) => ({
    // Pre-validate request data
    validatedBody: body ? validateAndTransform(userCreateSchema, body) : undefined,
    validatedQuery: query ? validateAndTransform(paginationSchema, query) : undefined,
    validatedParams: params ? validateAndTransform(userParamsSchema, params) : undefined,
  }))
  .post('/', async ({ validatedBody }) => {
    // validatedBody is already validated and typed
    const user = await createUser(validatedBody);
    return createSuccessResponse({ user });
  });
```

## Error Monitoring and Logging

### Structured Error Logging

```typescript
import { createLogger, format, transports } from 'winston';

export const logger = createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: format.combine(
    format.timestamp(),
    format.errors({ stack: true }),
    format.json()
  ),
  transports: [
    new transports.Console({
      format: format.combine(
        format.colorize(),
        format.simple()
      )
    }),
    new transports.File({ 
      filename: 'logs/error.log', 
      level: 'error' 
    }),
    new transports.File({ 
      filename: 'logs/combined.log' 
    }),
  ],
});

// Error context interface
export interface ErrorContext {
  userId?: string;
  requestId?: string;
  userAgent?: string;
  ipAddress?: string;
  additionalData?: Record<string, any>;
}

// Enhanced error logging
export function logError(
  error: Error,
  context: ErrorContext = {},
  level: 'error' | 'warn' = 'error'
): void {
  const errorInfo = {
    message: error.message,
    stack: error.stack,
    name: error.name,
    timestamp: new Date().toISOString(),
    ...context,
  };
  
  logger[level]('Application error', errorInfo);
  
  // Send to external monitoring service in production
  if (process.env.NODE_ENV === 'production') {
    sendToMonitoring(errorInfo);
  }
}

async function sendToMonitoring(errorInfo: any): Promise<void> {
  // Integration with Sentry, LogRocket, etc.
  if (process.env.SENTRY_DSN) {
    // Send to Sentry
  }
}
```

### Error Metrics and Alerting

```typescript
// Error metrics collection
export class ErrorMetrics {
  private static errorCounts = new Map<string, number>();
  
  static incrementError(errorCode: string): void {
    const current = this.errorCounts.get(errorCode) || 0;
    this.errorCounts.set(errorCode, current + 1);
  }
  
  static getErrorStats(): Record<string, number> {
    return Object.fromEntries(this.errorCounts);
  }
  
  static resetErrorStats(): void {
    this.errorCounts.clear();
  }
}

// Enhanced error handler with metrics
export const errorHandlerWithMetrics = new Elysia({ name: 'error-handler-metrics' })
  .use(errorHandler)
  .onError(({ error, code }) => {
    // Track error metrics
    if (error instanceof BaseError) {
      ErrorMetrics.incrementError(error.code);
    } else {
      ErrorMetrics.incrementError('UNKNOWN_ERROR');
    }
    
    // Send alerts for critical errors
    if (error instanceof AccountLockedError || 
        error instanceof AuthenticationError) {
      sendSecurityAlert(error);
    }
  })
  .as('global');

async function sendSecurityAlert(error: BaseError): Promise<void> {
  // Send to security monitoring system
  logger.error('Security alert', {
    errorCode: error.code,
    message: error.message,
    timestamp: error.timestamp,
  });
}
```

## Testing Error Scenarios

### Error Testing Utilities

```typescript
// Test helpers for error scenarios
export class ErrorTestUtils {
  static async expectError<T extends BaseError>(
    fn: () => Promise<any>,
    errorClass: new (...args: any[]) => T
  ): Promise<T> {
    try {
      await fn();
      throw new Error(`Expected ${errorClass.name} to be thrown`);
    } catch (error) {
      if (error instanceof errorClass) {
        return error;
      }
      throw error;
    }
  }
  
  static async expectValidationError(
    fn: () => Promise<any>,
    field?: string
  ): Promise<ValidationError> {
    const error = await this.expectError(fn, ValidationError);
    
    if (field && error.details) {
      const fieldError = error.details.find((e: any) => e.field === field);
      if (!fieldError) {
        throw new Error(`Expected validation error for field: ${field}`);
      }
    }
    
    return error;
  }
}

// Example test
describe('Authentication Errors', () => {
  it('should throw InvalidCredentialsError for wrong password', async () => {
    const error = await ErrorTestUtils.expectError(
      () => authService.login('user@example.com', 'wrongpassword'),
      InvalidCredentialsError
    );
    
    expect(error.code).toBe('INVALID_CREDENTIALS');
    expect(error.statusCode).toBe(401);
  });
  
  it('should throw ValidationError for invalid email', async () => {
    const error = await ErrorTestUtils.expectValidationError(
      () => authService.register({ email: 'invalid-email' }),
      'email'
    );
    
    expect(error.details).toContainEqual({
      field: 'email',
      message: 'Must be a valid email address',
    });
  });
});
```

This error handling system provides comprehensive error management with proper typing, logging, monitoring, and testing support for the Tamatar Auth project.
