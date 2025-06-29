# Contributing Guide

Welcome to the Tamatar Auth microservice! This guide will help you understand how to contribute to the project effectively.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [Pull Request Process](#pull-request-process)
- [Release Process](#release-process)
- [Troubleshooting](#troubleshooting)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct:

- **Be respectful**: Treat everyone with respect and kindness
- **Be inclusive**: Welcome newcomers and help them learn
- **Be constructive**: Provide helpful feedback and suggestions
- **Be patient**: Remember that everyone has different experience levels
- **Be professional**: Keep discussions focused and productive

## Getting Started

### Prerequisites

Before contributing, ensure you have:

- **Bun**: Latest version (v1.0+)
- **Node.js**: v18+ (for compatibility)
- **PostgreSQL**: v13+ for local development
- **Git**: Latest version
- **Docker**: For containerized development (optional)
- **Code Editor**: VS Code recommended with suggested extensions

### First Time Setup

1. **Fork the repository**
   ```bash
   # Fork on GitHub, then clone your fork
   git clone https://github.com/your-username/tamatar-auth.git
   cd tamatar-auth
   ```

2. **Set up upstream remote**
   ```bash
   git remote add upstream https://github.com/tamatar/tamatar-auth.git
   ```

3. **Install dependencies**
   ```bash
   bun install
   ```

4. **Set up environment**
   ```bash
   cp .env.example .env
   # Edit .env with your local configuration
   ```

5. **Set up database**
   ```bash
   # Start PostgreSQL (if using Docker)
   docker run --name postgres-dev -e POSTGRES_PASSWORD=password -e POSTGRES_DB=tamatar_auth_dev -p 5432:5432 -d postgres:15

   # Run migrations
   bunx prisma migrate dev
   ```

6. **Verify setup**
   ```bash
   bun dev
   # Visit http://localhost:3000/health
   ```

## Development Setup

### Recommended VS Code Extensions

Create `.vscode/extensions.json`:

```json
{
  "recommendations": [
    "biomejs.biome",
    "bradlc.vscode-tailwindcss",
    "prisma.prisma",
    "ms-vscode.vscode-typescript-next",
    "ms-vscode.vscode-json",
    "redhat.vscode-yaml",
    "ms-vscode.test-adapter-converter"
  ]
}
```

### VS Code Settings

Create `.vscode/settings.json`:

```json
{
  "editor.formatOnSave": true,
  "editor.defaultFormatter": "biomejs.biome",
  "editor.codeActionsOnSave": {
    "quickfix.biome": "explicit",
    "source.organizeImports.biome": "explicit"
  },
  "typescript.preferences.importModuleSpecifier": "relative",
  "files.exclude": {
    "**/node_modules": true,
    "**/dist": true,
    "**/.next": true
  }
}
```

### Environment Configuration

```bash
# .env.development
NODE_ENV=development
PORT=3000
LOG_LEVEL=debug

# Database
DATABASE_URL="postgresql://postgres:password@localhost:5432/tamatar_auth_dev"

# JWT
JWT_SECRET="dev-secret-key-change-in-production"
JWT_EXPIRES_IN="7d"

# Email (use test credentials)
RESEND_API_KEY="re_test_key_here"
FROM_EMAIL="test@example.com"

# Optional: Enable debug features
ENABLE_SWAGGER=true
ENABLE_CORS=true
CORS_ORIGIN="http://localhost:3000,http://localhost:3001"
```

## Project Structure

Understanding the codebase structure:

```
tamatar-auth/
├── docs/                     # Documentation
├── prisma/                   # Database schema and migrations
│   ├── schema.prisma        # Database schema definition
│   ├── migrations/          # Database migration files
│   └── seed.ts              # Database seeding script
├── src/
│   ├── index.ts            # Application entry point
│   ├── routes/             # API route handlers
│   │   ├── auth.ts         # Authentication routes
│   │   ├── users.ts        # User management routes
│   │   └── health.ts       # Health check routes
│   ├── middleware/         # Custom middleware
│   │   ├── auth.ts         # Authentication middleware
│   │   ├── cors.ts         # CORS middleware
│   │   ├── rate-limit.ts   # Rate limiting middleware
│   │   └── error.ts        # Error handling middleware
│   ├── lib/                # Utility libraries
│   │   ├── db/             # Database utilities
│   │   │   ├── prisma.ts   # Prisma client configuration
│   │   │   ├── user.ts     # User repository
│   │   │   └── session.ts  # Session repository
│   │   ├── email/          # Email service
│   │   │   ├── resend.ts   # Resend integration
│   │   │   └── templates/  # Email templates
│   │   ├── auth/           # Authentication utilities
│   │   │   ├── jwt.ts      # JWT utilities
│   │   │   ├── password.ts # Password hashing
│   │   │   └── session.ts  # Session management
│   │   ├── validation/     # Input validation schemas
│   │   └── utils/          # General utilities
│   ├── types/              # TypeScript type definitions
│   └── generated/          # Generated code (Prisma client)
├── tests/                   # Test files
│   ├── unit/               # Unit tests
│   ├── integration/        # Integration tests
│   └── e2e/                # End-to-end tests
├── scripts/                # Build and deployment scripts
├── .github/                # GitHub Actions workflows
└── config files...
```

## Development Workflow

### Branch Naming Convention

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `test/description` - Test improvements
- `chore/description` - Maintenance tasks

Example: `feature/oauth-google-integration`

### Workflow Steps

1. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make changes**
   - Write code following our standards
   - Add tests for new functionality
   - Update documentation if needed

3. **Test your changes**
   ```bash
   # Run all tests
   bun test

   # Run specific test suites
   bun test:unit
   bun test:integration
   bun test:e2e

   # Run linting
   bun lint

   # Type checking
   bun type-check
   ```

4. **Commit changes**
   ```bash
   git add .
   git commit -m "feat: add Google OAuth integration"
   ```

5. **Push and create PR**
   ```bash
   git push origin feature/your-feature-name
   # Create PR on GitHub
   ```

## Coding Standards

### TypeScript Guidelines

- **Strict mode**: All TypeScript strict checks enabled
- **Explicit types**: Define explicit return types for functions
- **No `any`**: Avoid using `any` type, use `unknown` or proper types
- **Interface over type**: Prefer interfaces for object shapes

```typescript
// ✅ Good
interface UserCreateRequest {
  email: string;
  password: string;
  name?: string;
}

export async function createUser(data: UserCreateRequest): Promise<User> {
  // Implementation
}

// ❌ Bad
export async function createUser(data: any) {
  // Implementation
}
```

### Code Style

We use **Biome** for code formatting and linting:

```json
// biome.json
{
  "linter": {
    "enabled": true,
    "rules": {
      "recommended": true,
      "complexity": {
        "noExtraBooleanCast": "error",
        "noMultipleSpacesInRegularExpressionLiterals": "error"
      },
      "correctness": {
        "noConstAssign": "error",
        "noGlobalObjectCalls": "error"
      },
      "security": {
        "noDangerouslySetInnerHtml": "error"
      },
      "style": {
        "noVar": "error",
        "useConst": "error"
      }
    }
  },
  "formatter": {
    "enabled": true,
    "indentStyle": "space",
    "indentWidth": 2,
    "lineWidth": 100
  }
}
```

### Naming Conventions

- **Files**: `kebab-case.ts`
- **Variables/Functions**: `camelCase`
- **Classes/Interfaces**: `PascalCase`
- **Constants**: `SCREAMING_SNAKE_CASE`
- **Database tables**: `snake_case`

```typescript
// ✅ Good
const userRepository = new UserRepository();
const API_BASE_URL = "https://api.example.com";

interface UserProfile {
  id: string;
  email: string;
}

class EmailService {
  async sendWelcomeEmail(): Promise<void> {
    // Implementation
  }
}

// ❌ Bad
const UserRepo = new user_repository();
const apiBaseUrl = "https://api.example.com";
```

### Error Handling

- Use custom error classes
- Always handle async operations
- Provide meaningful error messages
- Log errors appropriately

```typescript
// ✅ Good
export class ValidationError extends Error {
  constructor(
    message: string,
    public field: string,
    public code: string = "VALIDATION_ERROR"
  ) {
    super(message);
    this.name = "ValidationError";
  }
}

export async function validateUser(data: unknown): Promise<UserCreateRequest> {
  try {
    return userCreateSchema.parse(data);
  } catch (error) {
    logger.error("User validation failed", { error, data });
    throw new ValidationError("Invalid user data", "user", "INVALID_DATA");
  }
}
```

### Database Guidelines

- **Migrations**: Always create migrations for schema changes
- **Transactions**: Use transactions for related operations
- **Indexing**: Add appropriate indexes for performance
- **Validation**: Validate data at application level too

```typescript
// ✅ Good
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

## Testing Requirements

### Test Structure

```
tests/
├── unit/                    # Unit tests (isolated component testing)
│   ├── lib/
│   │   ├── auth.test.ts
│   │   ├── email.test.ts
│   │   └── validation.test.ts
│   └── routes/
│       ├── auth.test.ts
│       └── users.test.ts
├── integration/             # Integration tests (multiple components)
│   ├── api/
│   │   ├── auth-flow.test.ts
│   │   └── user-management.test.ts
│   └── database/
│       └── user-repository.test.ts
└── e2e/                     # End-to-end tests (full user scenarios)
    ├── authentication.test.ts
    ├── email-verification.test.ts
    └── password-reset.test.ts
```

### Test Requirements

1. **Unit Tests**: Every utility function and class method
2. **Integration Tests**: API endpoints and database operations
3. **E2E Tests**: Critical user flows
4. **Coverage**: Maintain >80% code coverage

### Testing Examples

```typescript
// tests/unit/lib/auth.test.ts
import { describe, it, expect, beforeEach } from "bun:test";
import { JWTService } from "../../../src/lib/auth/jwt";

describe("JWTService", () => {
  let jwtService: JWTService;

  beforeEach(() => {
    jwtService = new JWTService("test-secret");
  });

  it("should generate and verify JWT tokens", async () => {
    const payload = { userId: "123", email: "test@example.com" };
    
    const token = await jwtService.sign(payload);
    expect(token).toBeTypeOf("string");
    
    const decoded = await jwtService.verify(token);
    expect(decoded.userId).toBe(payload.userId);
    expect(decoded.email).toBe(payload.email);
  });

  it("should throw error for invalid tokens", async () => {
    await expect(jwtService.verify("invalid-token")).rejects.toThrow();
  });
});
```

```typescript
// tests/integration/api/auth.test.ts
import { describe, it, expect, beforeEach, afterEach } from "bun:test";
import { app } from "../../../src/index";
import { clearDatabase, seedTestUser } from "../../helpers/database";

describe("Authentication API", () => {
  beforeEach(async () => {
    await clearDatabase();
  });

  afterEach(async () => {
    await clearDatabase();
  });

  it("should register a new user", async () => {
    const response = await app.handle(
      new Request("http://localhost/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "test@example.com",
          password: "SecurePass123!",
          name: "Test User",
        }),
      })
    );

    expect(response.status).toBe(201);
    const data = await response.json();
    expect(data.user.email).toBe("test@example.com");
    expect(data.token).toBeTypeOf("string");
  });

  it("should login existing user", async () => {
    await seedTestUser({
      email: "test@example.com",
      password: "SecurePass123!",
    });

    const response = await app.handle(
      new Request("http://localhost/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: "test@example.com",
          password: "SecurePass123!",
        }),
      })
    );

    expect(response.status).toBe(200);
    const data = await response.json();
    expect(data.token).toBeTypeOf("string");
  });
});
```

### Running Tests

```bash
# Run all tests
bun test

# Run specific test files
bun test tests/unit/lib/auth.test.ts

# Run tests in watch mode
bun test --watch

# Run tests with coverage
bun test --coverage

# Run only integration tests
bun test tests/integration

# Run tests matching pattern
bun test --test-name-pattern="JWT"
```

## Documentation

### Documentation Requirements

1. **Code Comments**: Document complex logic and business rules
2. **API Documentation**: Update OpenAPI specs for API changes
3. **README Updates**: Update relevant sections for new features
4. **Migration Guides**: Document breaking changes

### JSDoc Standards

```typescript
/**
 * Creates a new user account with email verification
 * 
 * @param userData - User registration data
 * @param userData.email - User's email address (must be unique)
 * @param userData.password - Plain text password (will be hashed)
 * @param userData.name - Optional display name
 * @returns Promise resolving to created user and JWT token
 * 
 * @throws {ValidationError} When user data is invalid
 * @throws {ConflictError} When email already exists
 * 
 * @example
 * ```typescript
 * const result = await createUser({
 *   email: "user@example.com",
 *   password: "SecurePass123!",
 *   name: "John Doe"
 * });
 * console.log(result.user.id);
 * ```
 */
export async function createUser(userData: UserCreateRequest): Promise<CreateUserResult> {
  // Implementation
}
```

### API Documentation

Update `src/swagger.ts` for API changes:

```typescript
export const registerSchema = {
  tags: ["Authentication"],
  summary: "Register a new user",
  description: "Creates a new user account and sends email verification",
  body: {
    type: "object",
    required: ["email", "password"],
    properties: {
      email: { type: "string", format: "email" },
      password: { type: "string", minLength: 8 },
      name: { type: "string", maxLength: 100 }
    }
  },
  response: {
    201: {
      description: "User created successfully",
      type: "object",
      properties: {
        user: { $ref: "#/components/schemas/User" },
        token: { type: "string" }
      }
    },
    400: { $ref: "#/components/responses/ValidationError" },
    409: { $ref: "#/components/responses/ConflictError" }
  }
};
```

## Pull Request Process

### PR Requirements

1. **Descriptive Title**: Use conventional commit format
2. **Detailed Description**: Explain what, why, and how
3. **Tests**: Include relevant tests
4. **Documentation**: Update docs if needed
5. **No Breaking Changes**: Without prior discussion

### PR Template

```markdown
## Description
Brief description of the changes made.

## Type of Change
- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New feature (non-breaking change that adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## How Has This Been Tested?
Describe the tests you ran and any relevant details.

## Checklist
- [ ] My code follows the project's style guidelines
- [ ] I have performed a self-review of my code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] My changes generate no new warnings
- [ ] I have added tests that prove my fix is effective or that my feature works
- [ ] New and existing unit tests pass locally with my changes

## Related Issues
Closes #(issue number)
```

### Review Process

1. **Automated Checks**: All CI checks must pass
2. **Code Review**: At least one approving review required
3. **Testing**: Manual testing in review environment
4. **Documentation**: Verify docs are updated
5. **Security**: Security review for sensitive changes

### Merge Guidelines

- Use **squash and merge** for feature branches
- Use **merge commit** for release branches
- Delete feature branches after merge
- Update local main branch after merge

## Release Process

### Versioning

We follow [Semantic Versioning](https://semver.org/):

- **MAJOR** (X.0.0): Breaking changes
- **MINOR** (0.X.0): New features (backward compatible)
- **PATCH** (0.0.X): Bug fixes (backward compatible)

### Release Steps

1. **Update Version**
   ```bash
   # Update package.json version
   bun version patch # or minor, major
   ```

2. **Create Release Branch**
   ```bash
   git checkout -b release/v1.2.3
   git push origin release/v1.2.3
   ```

3. **Create Release PR**
   - Update CHANGELOG.md
   - Update version in relevant files
   - Create PR to main branch

4. **Tag Release**
   ```bash
   git tag v1.2.3
   git push origin v1.2.3
   ```

5. **Deploy**
   - GitHub Actions will handle deployment
   - Monitor deployment status
   - Verify production health

### Changelog Format

```markdown
# Changelog

## [1.2.3] - 2024-01-15

### Added
- Google OAuth integration
- User profile management endpoints
- Enhanced email templates

### Changed
- Improved JWT token validation
- Updated database schema for better performance

### Fixed
- Email verification bug on mobile clients
- Rate limiting edge cases

### Security
- Updated dependencies with security patches
- Enhanced password validation rules
```

## Troubleshooting

### Common Development Issues

#### Database Issues

```bash
# Reset database
bunx prisma migrate reset

# Generate Prisma client
bunx prisma generate

# View database content
bunx prisma studio
```

#### TypeScript Errors

```bash
# Clear TypeScript cache
rm -rf node_modules/.cache

# Reinstall dependencies
rm -rf node_modules bun.lock
bun install

# Check types
bunx tsc --noEmit
```

#### Test Failures

```bash
# Clear test cache
rm -rf .bun-cache

# Run specific failing test
bun test tests/unit/specific-test.test.ts --verbose

# Debug test with console logs
bun test --debug
```

#### Port Already in Use

```bash
# Find process using port 3000
lsof -ti:3000

# Kill process
kill -9 $(lsof -ti:3000)

# Or use different port
PORT=3001 bun dev
```

### Getting Help

1. **Search Issues**: Check existing GitHub issues first
2. **Create Issue**: Use issue templates for bug reports/features
3. **Discord/Slack**: Join our community chat
4. **Documentation**: Check docs/ folder for detailed guides
5. **Code Review**: Ask for help in PR reviews

### Development Tools

#### Useful Scripts

```bash
# Development
bun dev              # Start development server
bun build            # Build for production
bun start            # Start production server

# Database
bun db:push          # Push schema changes
bun db:reset         # Reset database
bun db:seed          # Seed with test data
bun db:studio        # Open Prisma Studio

# Testing
bun test             # Run all tests
bun test:unit        # Run unit tests only
bun test:integration # Run integration tests
bun test:e2e         # Run e2e tests
bun test:coverage    # Run with coverage

# Code Quality
bun lint             # Run linter
bun format           # Format code
bun type-check       # Check TypeScript types
bun audit            # Security audit
```

#### IDE Setup

**VS Code Tasks** (`.vscode/tasks.json`):

```json
{
  "version": "2.0.0",
  "tasks": [
    {
      "label": "Dev Server",
      "type": "shell",
      "command": "bun dev",
      "group": "build",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      },
      "isBackground": true
    },
    {
      "label": "Run Tests",
      "type": "shell",
      "command": "bun test",
      "group": "test",
      "presentation": {
        "echo": true,
        "reveal": "always",
        "focus": false,
        "panel": "shared"
      }
    }
  ]
}
```

Thank you for contributing to Tamatar Auth! Your efforts help make authentication better for everyone in the Tamatar ecosystem. 🚀
