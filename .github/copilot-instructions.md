# GitHub Copilot Instructions for Tamatar Auth

This file provides context and instructions for GitHub Copilot to better assist with the Tamatar Auth microservice development.

## Project Overview

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

## Key Documentation References

When working on this project, reference these documentation files for context:

### Core Documentation
- [`docs/README.md`](../docs/README.md) - Project overview and architecture
- [`docs/getting-started.md`](../docs/getting-started.md) - Development setup
- [`docs/api-reference.md`](../docs/api-reference.md) - Complete API documentation

### Implementation Guides
- [`docs/auth-guide.md`](../docs/auth-guide.md) - Authentication patterns and flows
- [`docs/error-handling.md`](../docs/error-handling.md) - Error handling best practices
- [`docs/database.md`](../docs/database.md) - Database schema and operations
- [`docs/email.md`](../docs/email.md) - Email service implementation

### Operational Guides
- [`docs/security.md`](../docs/security.md) - Security practices and requirements
- [`docs/testing.md`](../docs/testing.md) - Testing strategies and examples
- [`docs/configuration.md`](../docs/configuration.md) - Environment and config management
- [`docs/deployment.md`](../docs/deployment.md) - Deployment configurations

### Development
- [`docs/contributing.md`](../docs/contributing.md) - Development workflow and standards

## Elysia.js Specific Patterns

When suggesting Elysia.js code, always consider:

### Plugin Architecture
- Use named plugins (`name: "plugin-name"`) for deduplication
- Apply proper scoping with `.as('scoped')` or `.as('global')`
- Separate concerns into reusable service plugins
- Use encapsulation by default (lifecycle hooks don't leak between plugins)

### Schema Management
- Define reference models with `.model()` for reusability
- Use TypeBox (`t.*`) for all validation schemas
- Reference models by name in route handlers
- Prefer schema inference over manual typing

### Lifecycle Hooks
- Use `guard` for applying middleware to multiple routes
- Use `resolve` for computed properties available in context
- Use `macro` for custom reusable hooks
- Use `beforeHandle` for authentication/authorization
- Use `onTransform` for request logging and modification

### Error Handling
- Use `onError` lifecycle for centralized error handling
- Return appropriate status codes with `status()` function
- Prefer throwing custom error classes over inline error responses

### Example Plugin Structure:
```typescript
// Service plugin (reusable across modules)
export const userService = new Elysia({ name: 'user/service' })
  .state({ users: new Map() })
  .model({
    auth: t.Object({
      email: t.String({ format: 'email' }),
      password: t.String({ minLength: 8 })
    })
  })
  .macro({
    isAuthenticated(enabled: boolean) {
      if (!enabled) return;
      return {
        beforeHandle: ({ status, headers }) => {
          if (!headers.authorization) {
            return status(401, { error: 'Unauthorized' });
          }
        }
      };
    }
  })
  .as('scoped');

// Controller plugin (specific routes)
export const authRoutes = new Elysia({ prefix: '/auth' })
  .use(userService)
  .post('/login', handler, { 
    body: 'auth',
    isAuthenticated: false 
  });
```

### TypeScript Standards
```typescript
// Prefer explicit types and interfaces
interface UserCreateRequest {
  email: string;
  password: string;
  name?: string;
}

// Use proper error handling
export async function createUser(data: UserCreateRequest): Promise<User> {
  try {
    // Implementation
  } catch (error) {
    logger.error("User creation failed", { error, data });
    throw new ValidationError("Invalid user data", "user");
  }
}
```

### Database Operations
```typescript
// Always use transactions for related operations
export async function createUserWithProfile(userData: UserCreateRequest) {
  return await db.$transaction(async (tx) => {
    const user = await tx.user.create({
      data: {
        email: userData.email,
        passwordHash: await hashPassword(userData.password),
      },
    });

    const profile = await tx.userProfile.create({
      data: {
        userId: user.id,
        name: userData.name,
      },
    });

    return { user, profile };
  });
}
```

### API Route Patterns
```typescript
// Use Elysia with proper validation and error handling
import { Elysia, t } from "elysia";
import { AuthError, ValidationError } from "../lib/errors";

export const authRoutes = new Elysia({ 
  prefix: "/auth",
  name: "auth" // Named plugin for deduplication
})
  .model({
    // Reference models for reusable schemas
    userAuth: t.Object({
      email: t.String({ format: "email" }),
      password: t.String({ minLength: 8 }),
    }),
    userProfile: t.Object({
      firstName: t.String({ maxLength: 50 }),
      lastName: t.Optional(t.String({ maxLength: 50 })),
    })
  })
  .guard({
    // Apply validation to multiple routes
    beforeHandle: ({ status, headers }) => {
      if (!headers.authorization) {
        return status(401, { error: "Missing authorization header" });
      }
    }
  })
  .post("/register", async ({ body, set }) => {
    try {
      const user = await createUser(body);
      set.status = 201;
      return { user, token: await generateToken(user) };
    } catch (error) {
      if (error instanceof ValidationError) {
        set.status = 400;
        return { error: error.message, code: error.code };
      }
      throw error;
    }
  }, {
    body: "userAuth" // Reference model by name
  })
  .as('scoped'); // Apply to parent when used as plugin
```

### Testing Patterns
```typescript
// Unit tests with proper setup/teardown
import { describe, it, expect, beforeEach } from "bun:test";

describe("AuthService", () => {
  let authService: AuthService;

  beforeEach(() => {
    authService = new AuthService();
  });

  it("should authenticate valid user", async () => {
    const result = await authService.authenticate({
      email: "test@example.com",
      password: "password123"
    });
    
    expect(result.user).toBeDefined();
    expect(result.token).toBeTypeOf("string");
  });
});
```

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

## Security Considerations

When suggesting code changes, always consider:
- Input validation and sanitization
- SQL injection prevention (use Prisma parameterized queries)
- JWT token security (proper signing, expiration)
- Password hashing (use bcrypt with proper salt rounds)
- Rate limiting for sensitive endpoints
- CORS configuration for production
- Environment variable handling for secrets
- Session management and cleanup

## Environment Variables

Reference these when suggesting configuration:
- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET` - JWT signing secret
- `RESEND_API_KEY` - Email service API key
- `NODE_ENV` - Environment (development/production)
- `PORT` - Server port (default: 3000)
- `LOG_LEVEL` - Logging level (debug/info/warn/error)

## Common Patterns

### Error Responses
```typescript
// Standard error response format
{
  "error": "Validation failed",
  "code": "VALIDATION_ERROR",
  "details": {
    "field": "email",
    "message": "Invalid email format"
  }
}
```

### Success Responses
```typescript
// Standard success response format
{
  "user": { /* user object */ },
  "token": "jwt-token-here",
  "expiresAt": "2024-01-01T00:00:00Z"
}
```

### Logging
```typescript
// Use structured logging
logger.info("User registered", {
  userId: user.id,
  email: user.email,
  timestamp: new Date().toISOString()
});
```

## Dependencies to Suggest

When suggesting new dependencies, prefer:
- Well-maintained packages with TypeScript support
- Packages compatible with Bun runtime
- Security-focused packages for auth-related functionality
- Lightweight alternatives when possible

## Testing Requirements

Always suggest tests when adding new functionality:
- Unit tests for utility functions
- Integration tests for API endpoints
- E2E tests for critical user flows
- Security tests for auth-related features

## Performance Considerations

- Use database connections efficiently (Prisma connection pooling)
- Implement proper caching for frequently accessed data
- Use background jobs for email sending
- Optimize database queries with proper indexing
- Consider rate limiting and request throttling

Refer to the documentation files for detailed implementation guidance and examples.

## Staying Current with Elysia.js

As Elysia.js evolves rapidly, always:
- Reference the latest [Elysia.js documentation](https://elysiajs.com/) for new features
- Check the [tutorial](https://elysiajs.com/tutorial.html) for updated patterns
- Update project documentation when adopting new Elysia.js features
- Maintain consistency between Elysia.js best practices and project patterns
- Consider performance and type safety improvements in new versions
