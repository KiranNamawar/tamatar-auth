# TypeScript Standards

This guide covers TypeScript coding standards and best practices for the Tamatar Auth project.

## Type Definitions

### Interface Conventions

```typescript
// ✅ Good - Explicit interfaces for API contracts
interface UserCreateRequest {
  email: string;
  password: string;
  firstName: string;
  lastName?: string;
}

interface UserResponse {
  id: string;
  email: string;
  firstName: string;
  lastName: string | null;
  emailVerified: boolean;
  createdAt: string;
  updatedAt: string;
}

// ❌ Bad - Using any or loosely typed objects
interface UserData {
  [key: string]: any;
}
```

### Function Signatures

```typescript
// ✅ Good - Explicit return types and parameter types
export async function createUser(data: UserCreateRequest): Promise<UserResponse> {
  try {
    const hashedPassword = await hashPassword(data.password);
    const user = await db.user.create({
      data: {
        ...data,
        password: hashedPassword,
      },
    });
    return sanitizeUser(user);
  } catch (error) {
    logger.error("User creation failed", { error, data });
    throw new ValidationError("Invalid user data", "user");
  }
}

// ❌ Bad - Implicit any types
export async function createUser(data) {
  // Implementation without type safety
}
```

### Error Handling Types

```typescript
// Custom error classes with proper typing
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

export class AuthenticationError extends Error {
  constructor(message: string, public code: string = "AUTH_ERROR") {
    super(message);
    this.name = "AuthenticationError";
  }
}

// Type guards for error handling
export function isValidationError(error: unknown): error is ValidationError {
  return error instanceof ValidationError;
}

export function isAuthenticationError(error: unknown): error is AuthenticationError {
  return error instanceof AuthenticationError;
}
```

## Elysia.js TypeScript Patterns

### Context Typing

```typescript
// Proper context destructuring with types
export const userRoutes = new Elysia({ name: 'user' })
  .resolve(({ headers }) => ({
    userId: extractUserIdFromToken(headers.authorization)
  }))
  .get('/profile', ({ userId, set }: { userId: string | null; set: any }) => {
    if (!userId) {
      set.status = 401;
      return { error: 'Unauthorized' };
    }
    return getUserProfile(userId);
  });

// Handler with full context typing
interface AuthenticatedContext {
  user: UserPayload;
  db: PrismaClient;
  set: ResponseSet;
  error: (code: number, message: string) => Response;
}

export const protectedHandler = ({ user, db, set, error }: AuthenticatedContext) => {
  // Implementation with full type safety
};
```

### Model Typing with TypeBox

```typescript
// Use TypeBox for runtime validation and static typing
import { t, Static } from '@sinclair/typebox';

// Define schemas
export const userCreateSchema = t.Object({
  email: t.String({ format: 'email' }),
  password: t.String({ minLength: 8 }),
  firstName: t.String({ minLength: 1, maxLength: 50 }),
  lastName: t.Optional(t.String({ maxLength: 50 }))
});

export const userResponseSchema = t.Object({
  id: t.String(),
  email: t.String(),
  firstName: t.String(),
  lastName: t.Union([t.String(), t.Null()]),
  emailVerified: t.Boolean(),
  createdAt: t.String({ format: 'date-time' }),
  updatedAt: t.String({ format: 'date-time' })
});

// Extract static types from schemas
export type UserCreateRequest = Static<typeof userCreateSchema>;
export type UserResponse = Static<typeof userResponseSchema>;

// Use in Elysia routes
export const authRoutes = new Elysia({ prefix: '/auth' })
  .model({
    userCreate: userCreateSchema,
    userResponse: userResponseSchema
  })
  .post('/register', async ({ body }: { body: UserCreateRequest }) => {
    // body is automatically typed and validated
    const user = await createUser(body);
    return { user };
  }, {
    body: 'userCreate',
    response: {
      201: t.Object({ user: t.Ref('userResponse') })
    }
  });
```

## Database Typing

### Prisma Type Integration

```typescript
// Import generated Prisma types
import type { User, Session, Prisma } from '../generated/prisma';

// Use Prisma types in service layer
export class UserService {
  async createUser(data: Prisma.UserCreateInput): Promise<User> {
    return await prisma.user.create({ data });
  }

  async findById(id: string): Promise<User | null> {
    return await prisma.user.findUnique({
      where: { id },
      include: {
        sessions: true,
        profile: true
      }
    });
  }

  async updateUser(
    id: string, 
    data: Prisma.UserUpdateInput
  ): Promise<User> {
    return await prisma.user.update({
      where: { id },
      data
    });
  }
}

// Repository pattern with proper typing
export interface UserRepository {
  create(data: Prisma.UserCreateInput): Promise<User>;
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  update(id: string, data: Prisma.UserUpdateInput): Promise<User>;
  delete(id: string): Promise<User>;
}

export class PrismaUserRepository implements UserRepository {
  constructor(private db: PrismaClient) {}

  async create(data: Prisma.UserCreateInput): Promise<User> {
    return await this.db.user.create({ data });
  }

  async findById(id: string): Promise<User | null> {
    return await this.db.user.findUnique({ where: { id } });
  }

  async findByEmail(email: string): Promise<User | null> {
    return await this.db.user.findUnique({ where: { email } });
  }

  async update(id: string, data: Prisma.UserUpdateInput): Promise<User> {
    return await this.db.user.update({ where: { id }, data });
  }

  async delete(id: string): Promise<User> {
    return await this.db.user.delete({ where: { id } });
  }
}
```

## Generic Types and Utilities

### API Response Types

```typescript
// Generic API response wrapper
export interface ApiResponse<T> {
  data: T;
  meta: {
    timestamp: string;
    requestId: string;
  };
}

export interface ApiError {
  error: {
    code: string;
    message: string;
    details?: any;
    timestamp: string;
    path: string;
  };
}

// Paginated response type
export interface PaginatedResponse<T> {
  data: T[];
  meta: {
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  };
}

// Query parameters type
export interface PaginationQuery {
  page?: number;
  limit?: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

// Helper function with generic typing
export function createApiResponse<T>(data: T): ApiResponse<T> {
  return {
    data,
    meta: {
      timestamp: new Date().toISOString(),
      requestId: generateRequestId()
    }
  };
}
```

### Service Layer Types

```typescript
// Service method result types
export type ServiceResult<T, E = Error> = {
  success: true;
  data: T;
} | {
  success: false;
  error: E;
};

export type AsyncServiceResult<T, E = Error> = Promise<ServiceResult<T, E>>;

// Authentication service types
export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface AuthenticationResult {
  user: UserResponse;
  tokens: AuthTokens;
  session: {
    id: string;
    expiresAt: string;
  };
}

// Service interface with proper typing
export interface AuthService {
  register(data: UserCreateRequest): AsyncServiceResult<AuthenticationResult>;
  login(email: string, password: string): AsyncServiceResult<AuthenticationResult>;
  refreshToken(refreshToken: string): AsyncServiceResult<AuthTokens>;
  logout(sessionId: string): AsyncServiceResult<void>;
  verifyEmail(token: string): AsyncServiceResult<UserResponse>;
}
```

## Type Guards and Validation

### Runtime Type Checking

```typescript
// Type guards for runtime validation
export function isString(value: unknown): value is string {
  return typeof value === 'string';
}

export function isNumber(value: unknown): value is number {
  return typeof value === 'number' && !isNaN(value);
}

export function isEmail(value: unknown): value is string {
  return isString(value) && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

export function isValidUser(value: unknown): value is UserResponse {
  if (!value || typeof value !== 'object') return false;
  const user = value as any;
  
  return (
    isString(user.id) &&
    isEmail(user.email) &&
    isString(user.firstName) &&
    (user.lastName === null || isString(user.lastName)) &&
    typeof user.emailVerified === 'boolean' &&
    isString(user.createdAt) &&
    isString(user.updatedAt)
  );
}

// Use type guards in request handlers
export const validateUserData = (data: unknown): UserCreateRequest => {
  if (!data || typeof data !== 'object') {
    throw new ValidationError('Invalid request data', 'body');
  }

  const userData = data as any;
  
  if (!isEmail(userData.email)) {
    throw new ValidationError('Invalid email format', 'email');
  }
  
  if (!isString(userData.password) || userData.password.length < 8) {
    throw new ValidationError('Password must be at least 8 characters', 'password');
  }
  
  if (!isString(userData.firstName) || userData.firstName.length === 0) {
    throw new ValidationError('First name is required', 'firstName');
  }

  return userData as UserCreateRequest;
};
```

### Conditional Types

```typescript
// Utility types for API responses
export type WithRequired<T, K extends keyof T> = T & Required<Pick<T, K>>;
export type WithOptional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>;

// Create variations of user types
export type UserCreate = WithRequired<Partial<User>, 'email' | 'password' | 'firstName'>;
export type UserUpdate = WithOptional<User, 'id' | 'createdAt' | 'updatedAt'>;
export type UserPublic = Omit<User, 'password' | 'emailVerificationToken'>;

// Conditional response types based on authentication
export type AuthenticatedResponse<T> = T & {
  user: UserResponse;
};

export type PublicResponse<T> = T;

// Helper to determine response type
export type ResponseType<T, Auth extends boolean> = Auth extends true 
  ? AuthenticatedResponse<T>
  : PublicResponse<T>;
```

## Configuration Types

### Environment Configuration

```typescript
// Environment variables with validation
export interface EnvironmentConfig {
  NODE_ENV: 'development' | 'test' | 'production';
  PORT: number;
  DATABASE_URL: string;
  JWT_SECRET: string;
  JWT_EXPIRES_IN: string;
  RESEND_API_KEY: string;
  FROM_EMAIL: string;
  CORS_ORIGIN: string;
  LOG_LEVEL: 'debug' | 'info' | 'warn' | 'error';
}

// Configuration validation with proper typing
export function validateEnvironment(): EnvironmentConfig {
  const env = process.env;
  
  const config: EnvironmentConfig = {
    NODE_ENV: (env.NODE_ENV as any) || 'development',
    PORT: parseInt(env.PORT || '3000', 10),
    DATABASE_URL: env.DATABASE_URL || '',
    JWT_SECRET: env.JWT_SECRET || '',
    JWT_EXPIRES_IN: env.JWT_EXPIRES_IN || '7d',
    RESEND_API_KEY: env.RESEND_API_KEY || '',
    FROM_EMAIL: env.FROM_EMAIL || '',
    CORS_ORIGIN: env.CORS_ORIGIN || '*',
    LOG_LEVEL: (env.LOG_LEVEL as any) || 'info'
  };
  
  // Validate required fields
  const required: (keyof EnvironmentConfig)[] = [
    'DATABASE_URL',
    'JWT_SECRET',
    'RESEND_API_KEY'
  ];
  
  for (const key of required) {
    if (!config[key]) {
      throw new Error(`Missing required environment variable: ${key}`);
    }
  }
  
  return config;
}
```

## Best Practices

### Naming Conventions

- **Interfaces**: Use PascalCase with descriptive names (`UserCreateRequest`, `AuthenticationResult`)
- **Types**: Use PascalCase for type aliases (`ResponseType`, `ServiceResult`)
- **Generic Parameters**: Use single uppercase letters (`T`, `K`, `V`) or descriptive names (`TData`, `TError`)
- **Enums**: Use PascalCase with descriptive values (`enum UserRole { ADMIN = 'admin', USER = 'user' }`)

### Type Organization

```typescript
// Group related types together
export namespace Auth {
  export interface LoginRequest {
    email: string;
    password: string;
  }
  
  export interface LoginResponse {
    user: UserResponse;
    tokens: AuthTokens;
  }
  
  export interface RefreshRequest {
    refreshToken: string;
  }
  
  export interface RefreshResponse {
    tokens: AuthTokens;
  }
}

// Use module declaration for extending external types
declare module '@elysiajs/bearer' {
  interface BearerContext {
    bearerToken: string;
  }
}
```

### Avoid Common Pitfalls

```typescript
// ❌ Bad - Using any
function processData(data: any): any {
  return data.someProperty;
}

// ✅ Good - Using generics or specific types
function processData<T extends { someProperty: unknown }>(data: T): T['someProperty'] {
  return data.someProperty;
}

// ❌ Bad - Loose typing
interface ApiResponse {
  data: any;
  status: number;
}

// ✅ Good - Generic typing
interface ApiResponse<T> {
  data: T;
  status: number;
}

// ❌ Bad - Missing error handling types
async function fetchUser(id: string) {
  const user = await db.user.findUnique({ where: { id } });
  return user;
}

// ✅ Good - Explicit error handling
async function fetchUser(id: string): Promise<User> {
  const user = await db.user.findUnique({ where: { id } });
  if (!user) {
    throw new Error('User not found');
  }
  return user;
}
```

This TypeScript standards guide ensures type safety, maintainability, and consistency across the Tamatar Auth codebase.
