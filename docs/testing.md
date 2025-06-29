# Testing Guide

## Overview

This guide covers comprehensive testing strategies for the Tamatar Auth microservice, including unit tests, integration tests, end-to-end tests, and security testing.

## Testing Stack

- **Test Runner**: Bun's built-in test runner
- **Assertion Library**: Bun's built-in expect
- **Mocking**: Bun's built-in mock functions
- **Database Testing**: Test database with cleanup
- **API Testing**: Supertest-like functionality with Elysia
- **Load Testing**: Artillery or k6

## Test Structure

```
tests/
├── unit/                    # Unit tests
│   ├── lib/
│   │   ├── auth/
│   │   ├── db/
│   │   ├── email/
│   │   └── security/
│   └── utils/
├── integration/             # Integration tests
│   ├── auth/
│   ├── database/
│   └── email/
├── e2e/                    # End-to-end tests
│   ├── auth-flow.test.ts
│   ├── registration.test.ts
│   └── password-reset.test.ts
├── load/                   # Load tests
│   ├── login-load.test.ts
│   └── registration-load.test.ts
├── security/               # Security tests
│   ├── injection.test.ts
│   ├── rate-limiting.test.ts
│   └── xss.test.ts
├── fixtures/               # Test data and fixtures
├── helpers/                # Test utilities
└── setup/                  # Test setup and teardown
```

## Test Configuration

### Test Environment Setup

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
    await this.prisma.securityEvent.deleteMany();
    await this.prisma.loginAttempt.deleteMany();
    await this.prisma.passwordResetToken.deleteMany();
    await this.prisma.emailVerificationToken.deleteMany();
    await this.prisma.session.deleteMany();
    await this.prisma.userRole.deleteMany();
    await this.prisma.role.deleteMany();
    await this.prisma.user.deleteMany();
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
    } = {}
  ) {
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers,
    };

    if (options.token) {
      headers.Authorization = `Bearer ${options.token}`;
    }

    const request = new Request(`http://localhost${path}`, {
      method: method.toUpperCase(),
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    return await app.handle(request);
  }

  // Email mock helper
  static mockEmailService() {
    const emails: Array<{
      to: string;
      subject: string;
      content: string;
    }> = [];

    const mockSend = jest.fn().mockImplementation((email) => {
      emails.push(email);
      return Promise.resolve({ id: faker.string.uuid() });
    });

    return { emails, mockSend };
  }

  // Time travel utility
  static async timeTravel(milliseconds: number): Promise<void> {
    jest.advanceTimersByTime(milliseconds);
    await new Promise(resolve => setTimeout(resolve, 0));
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

  // Rate limiting helper
  static async simulateRateLimit(identifier: string, count: number): Promise<void> {
    const key = `rate_limit:${identifier}`;
    for (let i = 0; i < count; i++) {
      await TestEnvironment.redis.zadd(key, Date.now(), `${Date.now()}-${i}`);
    }
  }
}
```

## Unit Tests

### Authentication Service Tests

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

    it('should reject passwords with sequential characters', () => {
      const result = PasswordSecurity.validateStrength('Password123!');
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

### Rate Limiter Tests

```typescript
// tests/unit/lib/security/rate-limit.test.ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { RateLimiter } from '../../../../src/lib/security/rate-limit';
import { TestEnvironment } from '../../../setup/test-env';

describe('RateLimiter', () => {
  let rateLimiter: RateLimiter;

  beforeEach(() => {
    rateLimiter = new RateLimiter();
  });

  describe('checkLimit', () => {
    it('should allow requests within limit', async () => {
      const identifier = 'test-user';
      const windowMs = 60000; // 1 minute
      const maxRequests = 5;

      for (let i = 0; i < maxRequests; i++) {
        const result = await rateLimiter.checkLimit(
          identifier,
          windowMs,
          maxRequests
        );

        expect(result.allowed).toBe(true);
        expect(result.remaining).toBe(maxRequests - (i + 1));
      }
    });

    it('should block requests exceeding limit', async () => {
      const identifier = 'test-user';
      const windowMs = 60000;
      const maxRequests = 3;

      // Use up the limit
      for (let i = 0; i < maxRequests; i++) {
        await rateLimiter.checkLimit(identifier, windowMs, maxRequests);
      }

      // Next request should be blocked
      const result = await rateLimiter.checkLimit(
        identifier,
        windowMs,
        maxRequests
      );

      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
    });

    it('should reset after window expires', async () => {
      const identifier = 'test-user';
      const windowMs = 1000; // 1 second
      const maxRequests = 2;

      // Use up the limit
      for (let i = 0; i < maxRequests; i++) {
        await rateLimiter.checkLimit(identifier, windowMs, maxRequests);
      }

      // Should be blocked
      let result = await rateLimiter.checkLimit(identifier, windowMs, maxRequests);
      expect(result.allowed).toBe(false);

      // Wait for window to expire
      await new Promise(resolve => setTimeout(resolve, 1100));

      // Should be allowed again
      result = await rateLimiter.checkLimit(identifier, windowMs, maxRequests);
      expect(result.allowed).toBe(true);
    });

    it('should handle different identifiers independently', async () => {
      const windowMs = 60000;
      const maxRequests = 2;

      // User 1 uses up their limit
      for (let i = 0; i < maxRequests; i++) {
        await rateLimiter.checkLimit('user1', windowMs, maxRequests);
      }

      // User 1 should be blocked
      const user1Result = await rateLimiter.checkLimit('user1', windowMs, maxRequests);
      expect(user1Result.allowed).toBe(false);

      // User 2 should still be allowed
      const user2Result = await rateLimiter.checkLimit('user2', windowMs, maxRequests);
      expect(user2Result.allowed).toBe(true);
    });
  });

  describe('progressive delay', () => {
    it('should increase delay with repeated violations', async () => {
      const identifier = 'repeat-offender';

      const delay1 = await rateLimiter.getProggressiveDelay(identifier);
      const delay2 = await rateLimiter.getProggressiveDelay(identifier);
      const delay3 = await rateLimiter.getProggressiveDelay(identifier);

      expect(delay2).toBeGreaterThan(delay1);
      expect(delay3).toBeGreaterThan(delay2);
      expect(delay3).toBeLessThanOrEqual(30000); // Max 30 seconds
    });
  });
});
```

## Integration Tests

### Authentication Flow Tests

```typescript
// tests/integration/auth/auth-flow.test.ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { Elysia } from 'elysia';
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
      const userData = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        username: 'johndoe',
        password: 'SecurePassword123!',
      };

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
      const userData = {
        firstName: 'John',
        lastName: 'Doe',
        email: testUser.email, // Already exists
        username: 'johndoe',
        password: 'SecurePassword123!',
      };

      const response = await TestUtils.makeRequest(app, 'POST', '/register', {
        body: userData,
      });

      expect(response.status).toBe(409);

      const body = await response.json();
      expect(body.error.code).toBe('USER_ALREADY_EXISTS');
    });

    it('should reject weak passwords', async () => {
      const userData = {
        firstName: 'John',
        lastName: 'Doe',
        email: 'john.doe@example.com',
        username: 'johndoe',
        password: 'weak', // Too weak
      };

      const response = await TestUtils.makeRequest(app, 'POST', '/register', {
        body: userData,
      });

      expect(response.status).toBe(400);

      const body = await response.json();
      expect(body.error.code).toBe('WEAK_PASSWORD');
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

  describe('GET /me', () => {
    it('should return current user with valid token', async () => {
      const session = await TestUtils.createTestSession(testUser.id);
      const token = TestUtils.generateTestJWT(testUser, session);

      const response = await TestUtils.makeRequest(app, 'GET', '/me', {
        token,
      });

      expect(response.status).toBe(200);

      const body = await response.json();
      expect(body.data.user.id).toBe(testUser.id);
      expect(body.data.user.email).toBe(testUser.email);
    });

    it('should reject request without token', async () => {
      const response = await TestUtils.makeRequest(app, 'GET', '/me');

      expect(response.status).toBe(401);

      const body = await response.json();
      expect(body.error.code).toBe('MISSING_TOKEN');
    });

    it('should reject request with invalid token', async () => {
      const response = await TestUtils.makeRequest(app, 'GET', '/me', {
        token: 'invalid.token.here',
      });

      expect(response.status).toBe(401);

      const body = await response.json();
      expect(body.error.code).toBe('INVALID_TOKEN');
    });
  });

  describe('POST /logout', () => {
    it('should logout successfully', async () => {
      const session = await TestUtils.createTestSession(testUser.id);
      const token = TestUtils.generateTestJWT(testUser, session);

      const response = await TestUtils.makeRequest(app, 'POST', '/logout', {
        token,
      });

      expect(response.status).toBe(200);

      // Verify session was invalidated
      const dbSession = await TestUtils.assertSessionExists(session.id);
      expect(dbSession.isValid).toBe(false);
    });
  });
});
```

### Email Integration Tests

```typescript
// tests/integration/email/email-service.test.ts
import { describe, it, expect, beforeEach, jest } from 'bun:test';
import { EmailService } from '../../../src/lib/email/service';
import { EmailVerificationTemplate } from '../../../src/lib/email/templates/EmailVerification';
import { TestUtils } from '../../helpers/test-utils';

describe('Email Service Integration', () => {
  let emailService: EmailService;
  let testUser: any;

  beforeEach(async () => {
    testUser = await TestUtils.createTestUser();
    emailService = new EmailService();
  });

  describe('sendEmail', () => {
    it('should send verification email successfully', async () => {
      // Mock Resend API
      const mockSend = jest.fn().mockResolvedValue({
        data: { id: 'test-email-id' },
        error: null,
      });

      // Replace the actual send method
      emailService['resend'].emails.send = mockSend;

      const result = await emailService.sendEmail({
        to: testUser.email,
        subject: 'Verify your email',
        react: EmailVerificationTemplate({
          firstName: testUser.firstName,
          verificationUrl: 'https://example.com/verify?token=test',
        }),
      });

      expect(result.id).toBe('test-email-id');
      expect(mockSend).toHaveBeenCalledWith({
        from: 'Tamatar Auth <auth@email.tamatar.dev>',
        to: [testUser.email],
        subject: 'Verify your email',
        react: expect.any(Object),
        replyTo: undefined,
        tags: undefined,
      });
    });

    it('should handle email service errors', async () => {
      // Mock Resend API error
      const mockSend = jest.fn().mockResolvedValue({
        data: null,
        error: { message: 'API key invalid' },
      });

      emailService['resend'].emails.send = mockSend;

      await expect(
        emailService.sendEmail({
          to: testUser.email,
          subject: 'Test',
          react: 'Test content',
        })
      ).rejects.toThrow('Email service error');
    });
  });

  describe('sendBulkEmail', () => {
    it('should send multiple emails', async () => {
      const mockSend = jest.fn().mockResolvedValue({
        data: { id: 'test-email-id' },
        error: null,
      });

      emailService['resend'].emails.send = mockSend;

      const emails = [
        {
          to: 'user1@example.com',
          subject: 'Test 1',
          react: 'Content 1',
        },
        {
          to: 'user2@example.com',
          subject: 'Test 2',
          react: 'Content 2',
        },
      ];

      const results = await emailService.sendBulkEmail(emails);

      expect(results).toHaveLength(2);
      expect(mockSend).toHaveBeenCalledTimes(2);
    });
  });
});
```

## End-to-End Tests

### Complete Authentication Flow

```typescript
// tests/e2e/auth-flow.test.ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { TestUtils } from '../helpers/test-utils';
import { app } from '../../src/index';

describe('Complete Authentication Flow E2E', () => {
  it('should complete full registration and login flow', async () => {
    const userData = {
      firstName: 'John',
      lastName: 'Doe',
      email: 'john.doe@example.com',
      username: 'johndoe',
      password: 'SecurePassword123!',
    };

    // 1. Register user
    const registerResponse = await TestUtils.makeRequest(app, 'POST', '/register', {
      body: userData,
    });

    expect(registerResponse.status).toBe(201);
    const registerBody = await registerResponse.json();
    const userId = registerBody.data.user.id;

    // 2. Verify email (simulate clicking email link)
    // In real test, this would involve getting the token from the database
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

## Security Tests

### Injection Attack Tests

```typescript
// tests/security/injection.test.ts
import { describe, it, expect } from 'bun:test';
import { TestUtils } from '../helpers/test-utils';
import { app } from '../../src/index';

describe('Security - Injection Attacks', () => {
  describe('SQL Injection Prevention', () => {
    it('should prevent SQL injection in login', async () => {
      const maliciousPayloads = [
        "'; DROP TABLE users; --",
        "' OR '1'='1",
        "' UNION SELECT * FROM users --",
        "'; INSERT INTO users (email) VALUES ('hacker@evil.com'); --",
      ];

      for (const payload of maliciousPayloads) {
        const response = await TestUtils.makeRequest(app, 'POST', '/login', {
          body: {
            email: payload,
            password: 'password',
          },
        });

        // Should return 401 (invalid credentials) not 500 (server error)
        expect(response.status).toBe(401);
        
        const body = await response.json();
        expect(body.error.code).toBe('INVALID_CREDENTIALS');
      }

      // Verify users table still exists and functions
      const user = await TestUtils.createTestUser();
      expect(user).toBeDefined();
    });
  });

  describe('XSS Prevention', () => {
    it('should sanitize user input', async () => {
      const xssPayloads = [
        '<script>alert("xss")</script>',
        '"><script>alert("xss")</script>',
        "'; alert('xss'); //",
        '<img src="x" onerror="alert(\'xss\')">',
      ];

      for (const payload of xssPayloads) {
        const response = await TestUtils.makeRequest(app, 'POST', '/register', {
          body: {
            firstName: payload,
            lastName: 'Test',
            email: 'test@example.com',
            username: 'testuser',
            password: 'SecurePassword123!',
          },
        });

        if (response.status === 201) {
          const body = await response.json();
          // Name should be sanitized (no script tags)
          expect(body.data.user.firstName).not.toContain('<script>');
          expect(body.data.user.firstName).not.toContain('alert');
        }
      }
    });
  });

  describe('Path Traversal Prevention', () => {
    it('should prevent directory traversal in file uploads', async () => {
      const user = await TestUtils.createTestUser();
      const session = await TestUtils.createTestSession(user.id);
      const token = TestUtils.generateTestJWT(user, session);

      const maliciousPaths = [
        '../../../etc/passwd',
        '..\\..\\..\\windows\\system32\\config\\sam',
        '/etc/shadow',
        'C:\\Windows\\System32\\config\\SAM',
      ];

      for (const path of maliciousPaths) {
        const response = await TestUtils.makeRequest(app, 'POST', '/me/avatar', {
          token,
          body: { filename: path },
        });

        // Should reject with validation error, not attempt to access file
        expect(response.status).toBe(400);
      }
    });
  });
});
```

### Rate Limiting Tests

```typescript
// tests/security/rate-limiting.test.ts
import { describe, it, expect, beforeEach } from 'bun:test';
import { TestUtils } from '../helpers/test-utils';
import { app } from '../../src/index';

describe('Security - Rate Limiting', () => {
  beforeEach(async () => {
    // Clean rate limiting state
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

    it('should rate limit by IP address', async () => {
      const maxRequests = 100;
      const headers = { 'X-Forwarded-For': '192.168.1.100' };

      // Simulate many requests from same IP
      await TestUtils.simulateRateLimit('192.168.1.100', maxRequests + 1);

      const response = await TestUtils.makeRequest(app, 'GET', '/health', {
        headers,
      });

      expect(response.status).toBe(429);
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

  describe('Registration Rate Limiting', () => {
    it('should rate limit registration attempts', async () => {
      const maxAttempts = 3;

      // Make registration attempts up to limit
      for (let i = 0; i < maxAttempts; i++) {
        const response = await TestUtils.makeRequest(app, 'POST', '/register', {
          body: {
            firstName: 'Test',
            lastName: 'User',
            email: `test${i}@example.com`,
            username: `testuser${i}`,
            password: 'SecurePassword123!',
          },
        });

        expect(response.status).toBe(201);
      }

      // Next attempt should be rate limited
      const blockedResponse = await TestUtils.makeRequest(app, 'POST', '/register', {
        body: {
          firstName: 'Test',
          lastName: 'User',
          email: 'blocked@example.com',
          username: 'blockeduser',
          password: 'SecurePassword123!',
        },
      });

      expect(blockedResponse.status).toBe(429);
    });
  });
});
```

## Load Testing

### Basic Load Test

```typescript
// tests/load/login-load.test.ts
import { describe, it, expect } from 'bun:test';
import { TestUtils } from '../helpers/test-utils';
import { app } from '../../src/index';

describe('Load Testing - Login Endpoint', () => {
  it('should handle concurrent login requests', async () => {
    // Create test users
    const users = await Promise.all(
      Array.from({ length: 10 }, () =>
        TestUtils.createTestUser({ emailVerified: true })
      )
    );

    // Create concurrent login requests
    const loginPromises = users.map(user =>
      TestUtils.makeRequest(app, 'POST', '/login', {
        body: {
          email: user.email,
          password: 'TestPassword123!',
        },
      })
    );

    const startTime = Date.now();
    const responses = await Promise.all(loginPromises);
    const endTime = Date.now();

    // All requests should succeed
    for (const response of responses) {
      expect(response.status).toBe(200);
    }

    // Should complete within reasonable time (adjust as needed)
    const duration = endTime - startTime;
    expect(duration).toBeLessThan(5000); // 5 seconds

    console.log(`Completed ${responses.length} concurrent logins in ${duration}ms`);
  });

  it('should maintain performance under sustained load', async () => {
    const user = await TestUtils.createTestUser({ emailVerified: true });
    const concurrency = 5;
    const requestsPerWorker = 20;
    const totalRequests = concurrency * requestsPerWorker;

    const workers = Array.from({ length: concurrency }, async () => {
      const times: number[] = [];
      
      for (let i = 0; i < requestsPerWorker; i++) {
        const start = Date.now();
        
        const response = await TestUtils.makeRequest(app, 'POST', '/login', {
          body: {
            email: user.email,
            password: 'TestPassword123!',
          },
        });
        
        const end = Date.now();
        times.push(end - start);
        
        expect(response.status).toBe(200);
        
        // Small delay between requests
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      
      return times;
    });

    const startTime = Date.now();
    const workerResults = await Promise.all(workers);
    const endTime = Date.now();

    const allTimes = workerResults.flat();
    const avgResponseTime = allTimes.reduce((a, b) => a + b, 0) / allTimes.length;
    const maxResponseTime = Math.max(...allTimes);
    const totalDuration = endTime - startTime;

    console.log(`Load test results:
      Total requests: ${totalRequests}
      Total duration: ${totalDuration}ms
      Requests per second: ${(totalRequests / totalDuration * 1000).toFixed(2)}
      Average response time: ${avgResponseTime.toFixed(2)}ms
      Max response time: ${maxResponseTime}ms
    `);

    // Performance assertions
    expect(avgResponseTime).toBeLessThan(500); // Average under 500ms
    expect(maxResponseTime).toBeLessThan(2000); // Max under 2s
  });
});
```

## Test Scripts

### Package.json Test Scripts

```json
{
  "scripts": {
    "test": "bun test",
    "test:unit": "bun test tests/unit",
    "test:integration": "bun test tests/integration",
    "test:e2e": "bun test tests/e2e",
    "test:security": "bun test tests/security",
    "test:load": "bun test tests/load",
    "test:watch": "bun test --watch",
    "test:coverage": "bun test --coverage",
    "test:ci": "bun test --bail --coverage --reporter=junit",
    "test:setup": "bunx prisma migrate deploy && bunx prisma db seed",
    "test:teardown": "bunx prisma migrate reset --force"
  }
}
```

### CI/CD Test Configuration

```yaml
# .github/workflows/test.yml
name: Test Suite

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: tamatar_auth_test
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432
      
      redis:
        image: redis:7
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 6379:6379

    steps:
      - uses: actions/checkout@v3
      
      - uses: oven-sh/setup-bun@v1
        with:
          bun-version: latest
      
      - name: Install dependencies
        run: bun install
      
      - name: Setup test database
        run: bun run test:setup
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/tamatar_auth_test
      
      - name: Run unit tests
        run: bun run test:unit
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/tamatar_auth_test
          REDIS_URL: redis://localhost:6379/1
      
      - name: Run integration tests
        run: bun run test:integration
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/tamatar_auth_test
          REDIS_URL: redis://localhost:6379/1
      
      - name: Run security tests
        run: bun run test:security
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/tamatar_auth_test
          REDIS_URL: redis://localhost:6379/1
      
      - name: Generate coverage report
        run: bun run test:coverage
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/tamatar_auth_test
          REDIS_URL: redis://localhost:6379/1
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
```

This comprehensive testing suite ensures the Tamatar Auth microservice is thoroughly tested across all layers, from individual functions to complete user flows, security vulnerabilities, and performance under load.
