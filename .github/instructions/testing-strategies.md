# Testing Strategies

This guide covers comprehensive testing strategies for the Tamatar Auth project using Bun's test framework and Elysia.js testing patterns.

## Testing Framework Setup

### Test Environment Configuration

```typescript
// tests/setup/test-env.ts
import { beforeAll, afterAll, beforeEach, afterEach } from 'bun:test';
import { PrismaClient } from '../../src/generated/prisma';
import { Redis } from 'ioredis';

export class TestEnvironment {
  static prisma: PrismaClient;
  static redis: Redis;

  static async setupGlobal() {
    // Set test environment
    process.env.NODE_ENV = 'test';
    process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/tamatar_auth_test';
    process.env.REDIS_URL = 'redis://localhost:6379/1';
    process.env.JWT_SECRET = 'test-jwt-secret-key-for-testing-only';
    process.env.RESEND_API_KEY = 'test-resend-key';
    
    // Initialize test database
    this.prisma = new PrismaClient({
      datasources: {
        db: {
          url: process.env.DATABASE_URL,
        },
      },
    });

    // Initialize test Redis
    this.redis = new Redis(process.env.REDIS_URL);

    // Run migrations
    await this.runMigrations();
  }

  static async teardownGlobal() {
    await this.prisma.$disconnect();
    await this.redis.quit();
  }

  static async setupTest() {
    // Clean database before each test
    await this.cleanDatabase();
    
    // Clear Redis cache
    await this.redis.flushdb();
  }

  static async teardownTest() {
    // Clean up after test if needed
  }

  private static async runMigrations() {
    // Run database migrations for test environment
    const { execSync } = require('child_process');
    execSync('bunx prisma migrate deploy', {
      env: { ...process.env, DATABASE_URL: process.env.DATABASE_URL },
    });
  }

  private static async cleanDatabase() {
    // Clean all tables in reverse dependency order
    const tables = [
      'SecurityEvent',
      'LoginAttempt', 
      'PasswordResetToken',
      'EmailVerificationToken',
      'Session',
      'UserRole',
      'Role',
      'User'
    ];
    
    for (const table of tables) {
      await this.prisma[table.toLowerCase()].deleteMany();
    }
  }
}

// Global test setup
beforeAll(async () => {
  await TestEnvironment.setupGlobal();
});

afterAll(async () => {
  await TestEnvironment.teardownGlobal();
});

beforeEach(async () => {
  await TestEnvironment.setupTest();
});

afterEach(async () => {
  await TestEnvironment.teardownTest();
});
```

### Test Utilities

```typescript
// tests/helpers/test-utils.ts
import { faker } from '@faker-js/faker';
import { TestEnvironment } from '../setup/test-env';
import type { User, Session } from '../../src/generated/prisma';
import { PasswordSecurity } from '../../src/lib/security/password';
import { JWTSecurity } from '../../src/lib/security/jwt';

export class TestUtils {
  // User factory
  static async createTestUser(overrides: Partial<User> = {}): Promise<User> {
    const defaultUser = {
      firstName: faker.person.firstName(),
      lastName: faker.person.lastName(),
      email: faker.internet.email().toLowerCase(),
      username: faker.internet.userName().toLowerCase(),
      password: await PasswordSecurity.hash('TestPassword123!'),
      emailVerified: true,
      ...overrides,
    };

    return await TestEnvironment.prisma.user.create({
      data: defaultUser,
    });
  }

  // Session factory
  static async createTestSession(userId: string, overrides: Partial<Session> = {}): Promise<Session> {
    const defaultSession = {
      userId,
      userAgent: faker.internet.userAgent(),
      ipAddress: faker.internet.ip(),
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
      ...overrides,
    };

    return await TestEnvironment.prisma.session.create({
      data: defaultSession,
    });
  }

  // JWT token factory
  static generateTestJWT(user: User, session: Session): string {
    return JWTSecurity.generateAccessToken({
      sub: user.id,
      email: user.email,
      username: user.username,
      sessionId: session.id,
    });
  }

  // API request helper
  static async makeRequest(
    app: any,
    method: string,
    path: string,
    options: {
      body?: any;
      headers?: Record<string, string>;
      token?: string;
      query?: Record<string, string>;
    } = {}
  ) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (options.token) {
      headers.Authorization = `Bearer ${options.token}`;
    }

    let url = `http://localhost${path}`;
    if (options.query) {
      const searchParams = new URLSearchParams(options.query);
      url += `?${searchParams.toString()}`;
    }

    const request = new Request(url, {
      method: method.toUpperCase(),
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    return await app.handle(request);
  }

  // Database assertions
  static async assertUserExists(email: string): Promise<User> {
    const user = await TestEnvironment.prisma.user.findUnique({
      where: { email },
    });
    
    if (!user) {
      throw new Error(`User with email ${email} not found`);
    }
    
    return user;
  }

  static async assertSessionExists(sessionId: string): Promise<Session> {
    const session = await TestEnvironment.prisma.session.findUnique({
      where: { id: sessionId },
    });
    
    if (!session) {
      throw new Error(`Session with id ${sessionId} not found`);
    }
    
    return session;
  }

  // Mock email service
  static createMockEmailService() {
    const sentEmails: Array<{
      to: string;
      subject: string;
      html: string;
      timestamp: Date;
    }> = [];

    return {
      emails: sentEmails,
      sendEmail: async (to: string, subject: string, html: string) => {
        sentEmails.push({
          to,
          subject,
          html,
          timestamp: new Date(),
        });
        return { id: faker.string.uuid() };
      },
      clear: () => sentEmails.length = 0,
      findEmail: (predicate: (email: any) => boolean) => 
        sentEmails.find(predicate),
    };
  }

  // Time manipulation
  static async timeTravel(milliseconds: number): Promise<void> {
    jest.advanceTimersByTime(milliseconds);
    await new Promise(resolve => setTimeout(resolve, 0));
  }

  // Rate limiting helper
  static async simulateRateLimit(identifier: string, count: number): Promise<void> {
    const key = `rate_limit:${identifier}`;
    for (let i = 0; i < count; i++) {
      await TestEnvironment.redis.zadd(key, Date.now(), `${Date.now()}-${i}`);
    }
  }

  // Test data generators
  static generateUserData(overrides: any = {}) {
    return {
      firstName: faker.person.firstName(),
      lastName: faker.person.lastName(),
      email: faker.internet.email().toLowerCase(),
      username: faker.internet.userName().toLowerCase(),
      password: 'TestPassword123!',
      ...overrides,
    };
  }

  static generateLoginData(email?: string) {
    return {
      email: email || faker.internet.email().toLowerCase(),
      password: 'TestPassword123!',
    };
  }
}
```

## Unit Testing

### Service Layer Tests

```typescript
// tests/unit/lib/auth/jwt.test.ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { JWTSecurity } from '../../../../src/lib/auth/jwt';
import { TestUtils } from '../../../helpers/test-utils';

describe('JWTSecurity', () => {
  let testUser: any;
  let testSession: any;

  beforeEach(async () => {
    testUser = await TestUtils.createTestUser();
    testSession = await TestUtils.createTestSession(testUser.id);
  });

  describe('generateAccessToken', () => {
    it('should generate a valid JWT token', () => {
      const token = JWTSecurity.generateAccessToken({
        sub: testUser.id,
        email: testUser.email,
        username: testUser.username,
        sessionId: testSession.id,
      });

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.split('.')).toHaveLength(3); // JWT has 3 parts
    });

    it('should include required claims', () => {
      const token = JWTSecurity.generateAccessToken({
        sub: testUser.id,
        email: testUser.email,
        username: testUser.username,
        sessionId: testSession.id,
      });

      const payload = JWTSecurity.verifyToken(token);

      expect(payload.sub).toBe(testUser.id);
      expect(payload.email).toBe(testUser.email);
      expect(payload.username).toBe(testUser.username);
      expect(payload.sessionId).toBe(testSession.id);
      expect(payload.iss).toBe('tamatar-auth');
      expect(payload.aud).toBe('tamatar-services');
    });
  });

  describe('verifyToken', () => {
    it('should verify a valid token', () => {
      const token = JWTSecurity.generateAccessToken({
        sub: testUser.id,
        email: testUser.email,
        username: testUser.username,
        sessionId: testSession.id,
      });

      const payload = JWTSecurity.verifyToken(token);
      expect(payload).toBeDefined();
      expect(payload.sub).toBe(testUser.id);
    });

    it('should throw error for invalid token', () => {
      expect(() => {
        JWTSecurity.verifyToken('invalid.token.here');
      }).toThrow();
    });

    it('should throw error for expired token', () => {
      // Mock Date.now to create expired token
      const originalNow = Date.now;
      Date.now = () => originalNow() - 1000 * 60 * 60; // 1 hour ago

      const token = JWTSecurity.generateAccessToken({
        sub: testUser.id,
        email: testUser.email,
        username: testUser.username,
        sessionId: testSession.id,
      });

      Date.now = originalNow; // Restore

      expect(() => {
        JWTSecurity.verifyToken(token);
      }).toThrow('Token expired');
    });
  });
});
```

### Password Security Tests

```typescript
// tests/unit/lib/security/password.test.ts
import { describe, it, expect } from 'bun:test';
import { PasswordSecurity } from '../../../../src/lib/security/password';

describe('PasswordSecurity', () => {
  describe('validateStrength', () => {
    it('should accept strong passwords', () => {
      const strongPasswords = [
        'StrongPassword123!',
        'MyS3cur3P@ssw0rd',
        'C0mpl3x!P@ssw0rd',
      ];

      for (const password of strongPasswords) {
        const result = PasswordSecurity.validateStrength(password);
        expect(result.isValid).toBe(true);
        expect(result.errors).toHaveLength(0);
        expect(result.score).toBeGreaterThan(3);
      }
    });

    it('should reject weak passwords', () => {
      const weakPasswords = [
        'password',        // Too common
        '123456',         // Too simple
        'abc123',         // Too simple
        'PASSWORD',       // No lowercase/numbers/symbols
        'password123',    // No uppercase/symbols
      ];

      for (const password of weakPasswords) {
        const result = PasswordSecurity.validateStrength(password);
        expect(result.isValid).toBe(false);
        expect(result.errors.length).toBeGreaterThan(0);
      }
    });

    it('should reject passwords with repeated characters', () => {
      const result = PasswordSecurity.validateStrength('Password111!');
      expect(result.isValid).toBe(false);
      expect(result.errors).toContain('Password contains weak patterns (repeated or sequential characters)');
    });
  });

  describe('hash and verify', () => {
    it('should hash and verify passwords correctly', async () => {
      const password = 'TestPassword123!';
      const hash = await PasswordSecurity.hash(password);

      expect(hash).toBeDefined();
      expect(hash).not.toBe(password);
      expect(await PasswordSecurity.verify(password, hash)).toBe(true);
      expect(await PasswordSecurity.verify('wrongpassword', hash)).toBe(false);
    });

    it('should generate different hashes for same password', async () => {
      const password = 'TestPassword123!';
      const hash1 = await PasswordSecurity.hash(password);
      const hash2 = await PasswordSecurity.hash(password);

      expect(hash1).not.toBe(hash2);
      expect(await PasswordSecurity.verify(password, hash1)).toBe(true);
      expect(await PasswordSecurity.verify(password, hash2)).toBe(true);
    });
  });

  describe('generateSecure', () => {
    it('should generate secure passwords of specified length', () => {
      const lengths = [12, 16, 20, 24];

      for (const length of lengths) {
        const password = PasswordSecurity.generateSecure(length);
        expect(password).toHaveLength(length);
        
        const validation = PasswordSecurity.validateStrength(password);
        expect(validation.isValid).toBe(true);
      }
    });

    it('should generate different passwords each time', () => {
      const passwords = Array.from({ length: 10 }, () => 
        PasswordSecurity.generateSecure(16)
      );

      const uniquePasswords = new Set(passwords);
      expect(uniquePasswords.size).toBe(passwords.length);
    });
  });
});
```

## Integration Testing

### API Endpoint Tests

```typescript
// tests/integration/auth/auth-flow.test.ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { TestUtils } from '../../helpers/test-utils';
import { app } from '../../../src/index';

describe('Authentication Flow', () => {
  let testUser: any;

  beforeEach(async () => {
    testUser = await TestUtils.createTestUser({
      email: 'test@example.com',
      emailVerified: true,
    });
  });

  describe('POST /register', () => {
    it('should register a new user successfully', async () => {
      const userData = TestUtils.generateUserData({
        email: 'john.doe@example.com',
        username: 'johndoe',
      });

      const response = await TestUtils.makeRequest(app, 'POST', '/register', {
        body: userData,
      });

      expect(response.status).toBe(201);

      const body = await response.json();
      expect(body.data.user.email).toBe(userData.email);
      expect(body.data.user.emailVerified).toBe(false);
      expect(body.data.user.password).toBeUndefined(); // Shouldn't return password

      // Verify user was created in database
      const dbUser = await TestUtils.assertUserExists(userData.email);
      expect(dbUser.firstName).toBe(userData.firstName);
    });

    it('should reject registration with existing email', async () => {
      const userData = TestUtils.generateUserData({
        email: testUser.email, // Already exists
      });

      const response = await TestUtils.makeRequest(app, 'POST', '/register', {
        body: userData,
      });

      expect(response.status).toBe(409);

      const body = await response.json();
      expect(body.error.code).toBe('USER_ALREADY_EXISTS');
    });

    it('should validate required fields', async () => {
      const response = await TestUtils.makeRequest(app, 'POST', '/register', {
        body: {
          email: 'invalid-email',
          password: 'weak',
        },
      });

      expect(response.status).toBe(400);

      const body = await response.json();
      expect(body.error.code).toBe('VALIDATION_ERROR');
      expect(body.error.details).toBeArray();
    });
  });

  describe('POST /login', () => {
    it('should login with valid credentials', async () => {
      const response = await TestUtils.makeRequest(app, 'POST', '/login', {
        body: {
          email: testUser.email,
          password: 'TestPassword123!',
        },
      });

      expect(response.status).toBe(200);

      const body = await response.json();
      expect(body.data.user.email).toBe(testUser.email);
      expect(body.data.tokens.accessToken).toBeDefined();
      expect(body.data.tokens.refreshToken).toBeDefined();
      expect(body.data.session.id).toBeDefined();

      // Verify session was created
      await TestUtils.assertSessionExists(body.data.session.id);
    });

    it('should reject invalid credentials', async () => {
      const response = await TestUtils.makeRequest(app, 'POST', '/login', {
        body: {
          email: testUser.email,
          password: 'wrongpassword',
        },
      });

      expect(response.status).toBe(401);

      const body = await response.json();
      expect(body.error.code).toBe('INVALID_CREDENTIALS');
    });

    it('should reject unverified email', async () => {
      const unverifiedUser = await TestUtils.createTestUser({
        emailVerified: false,
      });

      const response = await TestUtils.makeRequest(app, 'POST', '/login', {
        body: {
          email: unverifiedUser.email,
          password: 'TestPassword123!',
        },
      });

      expect(response.status).toBe(409);

      const body = await response.json();
      expect(body.error.code).toBe('EMAIL_NOT_VERIFIED');
    });
  });

  describe('Authentication middleware', () => {
    it('should allow access with valid token', async () => {
      const session = await TestUtils.createTestSession(testUser.id);
      const token = TestUtils.generateTestJWT(testUser, session);

      const response = await TestUtils.makeRequest(app, 'GET', '/me', {
        token,
      });

      expect(response.status).toBe(200);

      const body = await response.json();
      expect(body.data.user.id).toBe(testUser.id);
    });

    it('should reject request without token', async () => {
      const response = await TestUtils.makeRequest(app, 'GET', '/me');

      expect(response.status).toBe(401);

      const body = await response.json();
      expect(body.error.code).toBe('MISSING_TOKEN');
    });

    it('should reject invalid token', async () => {
      const response = await TestUtils.makeRequest(app, 'GET', '/me', {
        token: 'invalid.token.here',
      });

      expect(response.status).toBe(401);

      const body = await response.json();
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });
});
```

### Database Integration Tests

```typescript
// tests/integration/database/user-repository.test.ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { UserRepository } from '../../../src/lib/db/user';
import { TestUtils, TestEnvironment } from '../../helpers/test-utils';

describe('UserRepository', () => {
  let userRepository: UserRepository;

  beforeEach(() => {
    userRepository = new UserRepository();
  });

  describe('create', () => {
    it('should create a new user', async () => {
      const userData = TestUtils.generateUserData();
      
      const user = await userRepository.create(userData);
      
      expect(user.id).toBeDefined();
      expect(user.email).toBe(userData.email);
      expect(user.firstName).toBe(userData.firstName);
      expect(user.emailVerified).toBe(false);
      expect(user.createdAt).toBeInstanceOf(Date);
    });

    it('should throw error for duplicate email', async () => {
      const userData = TestUtils.generateUserData();
      
      await userRepository.create(userData);
      
      await expect(
        userRepository.create(userData)
      ).rejects.toThrow();
    });
  });

  describe('findByEmail', () => {
    it('should find user by email', async () => {
      const userData = TestUtils.generateUserData();
      const createdUser = await userRepository.create(userData);
      
      const foundUser = await userRepository.findByEmail(userData.email);
      
      expect(foundUser).toBeDefined();
      expect(foundUser?.id).toBe(createdUser.id);
      expect(foundUser?.email).toBe(userData.email);
    });

    it('should return null for non-existent email', async () => {
      const user = await userRepository.findByEmail('nonexistent@example.com');
      
      expect(user).toBeNull();
    });
  });

  describe('update', () => {
    it('should update user fields', async () => {
      const userData = TestUtils.generateUserData();
      const user = await userRepository.create(userData);
      
      const updateData = {
        firstName: 'Updated Name',
        emailVerified: true,
      };
      
      const updatedUser = await userRepository.update(user.id, updateData);
      
      expect(updatedUser.firstName).toBe(updateData.firstName);
      expect(updatedUser.emailVerified).toBe(true);
      expect(updatedUser.updatedAt.getTime()).toBeGreaterThan(user.updatedAt.getTime());
    });
  });

  describe('transaction handling', () => {
    it('should rollback on transaction failure', async () => {
      const userData = TestUtils.generateUserData();
      
      await expect(
        TestEnvironment.prisma.$transaction(async (tx) => {
          await tx.user.create({ data: userData });
          // Force transaction failure
          throw new Error('Transaction failed');
        })
      ).rejects.toThrow('Transaction failed');
      
      // Verify user was not created
      const user = await userRepository.findByEmail(userData.email);
      expect(user).toBeNull();
    });
  });
});
```

## End-to-End Testing

### Complete User Flows

```typescript
// tests/e2e/complete-auth-flow.test.ts
import { describe, it, expect } from 'bun:test';
import { TestUtils, TestEnvironment } from '../helpers/test-utils';
import { app } from '../../src/index';

describe('Complete Authentication Flow E2E', () => {
  it('should complete full registration and login flow', async () => {
    const userData = TestUtils.generateUserData({
      email: 'john.doe@example.com',
      username: 'johndoe',
    });

    // 1. Register user
    const registerResponse = await TestUtils.makeRequest(app, 'POST', '/register', {
      body: userData,
    });

    expect(registerResponse.status).toBe(201);
    const registerBody = await registerResponse.json();
    const userId = registerBody.data.user.id;

    // 2. Simulate email verification
    const verificationToken = await TestEnvironment.prisma.emailVerificationToken.create({
      data: {
        userId,
        token: 'test-verification-token',
        expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
      },
    });

    const verifyResponse = await TestUtils.makeRequest(app, 'POST', '/verify-email', {
      body: { token: verificationToken.token },
    });

    expect(verifyResponse.status).toBe(200);

    // 3. Login with verified account
    const loginResponse = await TestUtils.makeRequest(app, 'POST', '/login', {
      body: {
        email: userData.email,
        password: userData.password,
      },
    });

    expect(loginResponse.status).toBe(200);
    const loginBody = await loginResponse.json();
    expect(loginBody.data.tokens.accessToken).toBeDefined();

    // 4. Access protected route
    const meResponse = await TestUtils.makeRequest(app, 'GET', '/me', {
      token: loginBody.data.tokens.accessToken,
    });

    expect(meResponse.status).toBe(200);
    const meBody = await meResponse.json();
    expect(meBody.data.user.email).toBe(userData.email);
    expect(meBody.data.user.emailVerified).toBe(true);

    // 5. Update profile
    const updateResponse = await TestUtils.makeRequest(app, 'PATCH', '/me', {
      token: loginBody.data.tokens.accessToken,
      body: { firstName: 'Jane' },
    });

    expect(updateResponse.status).toBe(200);
    const updateBody = await updateResponse.json();
    expect(updateBody.data.user.firstName).toBe('Jane');

    // 6. Logout
    const logoutResponse = await TestUtils.makeRequest(app, 'POST', '/logout', {
      token: loginBody.data.tokens.accessToken,
    });

    expect(logoutResponse.status).toBe(200);

    // 7. Verify token is invalidated
    const postLogoutResponse = await TestUtils.makeRequest(app, 'GET', '/me', {
      token: loginBody.data.tokens.accessToken,
    });

    expect(postLogoutResponse.status).toBe(401);
  });

  it('should handle password reset flow', async () => {
    // 1. Create verified user
    const user = await TestUtils.createTestUser({
      email: 'reset@example.com',
      emailVerified: true,
    });

    // 2. Request password reset
    const resetRequestResponse = await TestUtils.makeRequest(app, 'POST', '/forgot-password', {
      body: { email: user.email },
    });

    expect(resetRequestResponse.status).toBe(200);

    // 3. Get reset token from database
    const resetToken = await TestEnvironment.prisma.passwordResetToken.findFirst({
      where: { userId: user.id },
      orderBy: { createdAt: 'desc' },
    });

    expect(resetToken).toBeDefined();

    // 4. Reset password
    const newPassword = 'NewSecurePassword123!';
    const resetResponse = await TestUtils.makeRequest(app, 'POST', '/reset-password', {
      body: {
        token: resetToken!.token,
        newPassword,
      },
    });

    expect(resetResponse.status).toBe(200);

    // 5. Login with new password
    const loginResponse = await TestUtils.makeRequest(app, 'POST', '/login', {
      body: {
        email: user.email,
        password: newPassword,
      },
    });

    expect(loginResponse.status).toBe(200);

    // 6. Verify old password doesn't work
    const oldPasswordResponse = await TestUtils.makeRequest(app, 'POST', '/login', {
      body: {
        email: user.email,
        password: 'TestPassword123!', // Old password
      },
    });

    expect(oldPasswordResponse.status).toBe(401);
  });
});
```

## Security Testing

### Rate Limiting Tests

```typescript
// tests/security/rate-limiting.test.ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { TestUtils, TestEnvironment } from '../helpers/test-utils';
import { app } from '../../src/index';

describe('Security - Rate Limiting', () => {
  beforeEach(async () => {
    // Clear rate limiting state
    await TestEnvironment.redis.flushdb();
  });

  describe('Login Rate Limiting', () => {
    it('should rate limit login attempts', async () => {
      const email = 'test@example.com';
      const maxAttempts = 5;

      // Make failed login attempts up to limit
      for (let i = 0; i < maxAttempts; i++) {
        const response = await TestUtils.makeRequest(app, 'POST', '/login', {
          body: {
            email,
            password: 'wrongpassword',
          },
        });

        expect(response.status).toBe(401);
      }

      // Next attempt should be rate limited
      const blockedResponse = await TestUtils.makeRequest(app, 'POST', '/login', {
        body: {
          email,
          password: 'wrongpassword',
        },
      });

      expect(blockedResponse.status).toBe(429);
      
      const body = await blockedResponse.json();
      expect(body.error.code).toBe('RATE_LIMIT_EXCEEDED');
    });

    it('should not rate limit successful logins', async () => {
      const user = await TestUtils.createTestUser({
        emailVerified: true,
      });

      // Make successful logins (should not be rate limited)
      for (let i = 0; i < 10; i++) {
        const response = await TestUtils.makeRequest(app, 'POST', '/login', {
          body: {
            email: user.email,
            password: 'TestPassword123!',
          },
        });

        expect(response.status).toBe(200);
      }
    });
  });
});
```

## Test Scripts and Configuration

### Package.json Test Scripts

```json
{
  "scripts": {
    "test": "bun test",
    "test:unit": "bun test tests/unit",
    "test:integration": "bun test tests/integration",
    "test:e2e": "bun test tests/e2e", 
    "test:security": "bun test tests/security",
    "test:watch": "bun test --watch",
    "test:coverage": "bun test --coverage",
    "test:ci": "bun test --bail --coverage --reporter=junit",
    "test:setup": "bunx prisma migrate deploy && bunx prisma db seed",
    "test:teardown": "bunx prisma migrate reset --force"
  }
}
```

### Test Configuration

```typescript
// tests/config/test.config.ts
export const testConfig = {
  timeout: 30000,
  retries: 2,
  testPathPattern: /\.(test|spec)\.(ts|js)$/,
  setupFilesAfterEnv: ['<rootDir>/tests/setup/test-env.ts'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  collectCoverageFrom: [
    'src/**/*.{ts,js}',
    '!src/**/*.d.ts',
    '!src/generated/**',
  ],
};
```

This comprehensive testing strategy ensures thorough coverage of the Tamatar Auth codebase with proper isolation, utilities, and realistic test scenarios.
