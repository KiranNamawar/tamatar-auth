# Security Best Practices

## Overview

This guide covers comprehensive security best practices for the Tamatar Auth microservice, including authentication security, data protection, API security, and operational security measures.

## Authentication Security

### 1. Password Security

#### Password Requirements

```typescript
// src/lib/security/password.ts
import bcrypt from 'bcryptjs';
import { config } from '../config';

export class PasswordSecurity {
  private static readonly SALT_ROUNDS = 12;
  private static readonly MIN_LENGTH = config.get().security.password.minLength;
  
  static async hash(password: string): Promise<string> {
    // Use high cost factor for bcrypt
    return await bcrypt.hash(password, this.SALT_ROUNDS);
  }

  static async verify(password: string, hash: string): Promise<boolean> {
    return await bcrypt.compare(password, hash);
  }

  static validateStrength(password: string): {
    isValid: boolean;
    errors: string[];
    score: number;
  } {
    const errors: string[] = [];
    let score = 0;

    // Length check
    if (password.length < this.MIN_LENGTH) {
      errors.push(`Password must be at least ${this.MIN_LENGTH} characters long`);
    } else {
      score += 1;
    }

    // Character variety checks
    if (!/[a-z]/.test(password)) {
      errors.push('Password must contain at least one lowercase letter');
    } else {
      score += 1;
    }

    if (!/[A-Z]/.test(password)) {
      errors.push('Password must contain at least one uppercase letter');
    } else {
      score += 1;
    }

    if (!/\d/.test(password)) {
      errors.push('Password must contain at least one number');
    } else {
      score += 1;
    }

    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
      errors.push('Password must contain at least one special character');
    } else {
      score += 1;
    }

    // Common password check
    if (this.isCommonPassword(password)) {
      errors.push('Password is too common. Please choose a different password');
      score -= 2;
    }

    // Sequential/repeated character check
    if (this.hasWeakPatterns(password)) {
      errors.push('Password contains weak patterns (repeated or sequential characters)');
      score -= 1;
    }

    return {
      isValid: errors.length === 0,
      errors,
      score: Math.max(0, score),
    };
  }

  private static isCommonPassword(password: string): boolean {
    const commonPasswords = [
      'password', 'password123', '123456', '123456789', 'qwerty',
      'abc123', 'password1', 'admin', 'letmein', 'welcome',
      'monkey', '1234567890', 'dragon', 'master', 'iloveyou'
    ];
    
    return commonPasswords.includes(password.toLowerCase());
  }

  private static hasWeakPatterns(password: string): boolean {
    // Check for repeated characters (3+ in a row)
    if (/(.)\1{2,}/.test(password)) return true;
    
    // Check for sequential characters
    for (let i = 0; i < password.length - 2; i++) {
      const char1 = password.charCodeAt(i);
      const char2 = password.charCodeAt(i + 1);
      const char3 = password.charCodeAt(i + 2);
      
      if (char2 === char1 + 1 && char3 === char2 + 1) {
        return true; // Sequential ascending
      }
      if (char2 === char1 - 1 && char3 === char2 - 1) {
        return true; // Sequential descending
      }
    }
    
    return false;
  }

  static generateSecure(length: number = 16): string {
    const charset = {
      lowercase: 'abcdefghijklmnopqrstuvwxyz',
      uppercase: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
      numbers: '0123456789',
      symbols: '!@#$%^&*()_+-=[]{}|;:,.<>?'
    };

    const allChars = Object.values(charset).join('');
    let password = '';

    // Ensure at least one character from each set
    password += this.randomChar(charset.lowercase);
    password += this.randomChar(charset.uppercase);
    password += this.randomChar(charset.numbers);
    password += this.randomChar(charset.symbols);

    // Fill remaining length with random characters
    for (let i = 4; i < length; i++) {
      password += this.randomChar(allChars);
    }

    // Shuffle the password
    return password.split('').sort(() => 0.5 - Math.random()).join('');
  }

  private static randomChar(charset: string): string {
    return charset.charAt(Math.floor(Math.random() * charset.length));
  }
}
```

### 2. JWT Security

#### Secure JWT Implementation

```typescript
// src/lib/security/jwt.ts
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { config } from '../config';

export class JWTSecurity {
  private static readonly ALGORITHM = 'HS256';
  private static readonly SECRET = config.get().jwt.secret;
  
  static generateAccessToken(payload: Record<string, any>): string {
    // Add security claims
    const tokenPayload = {
      ...payload,
      jti: crypto.randomUUID(), // JWT ID for token blacklisting
      iat: Math.floor(Date.now() / 1000),
      nbf: Math.floor(Date.now() / 1000), // Not before
    };

    return jwt.sign(tokenPayload, this.SECRET, {
      algorithm: this.ALGORITHM,
      expiresIn: config.get().jwt.accessTokenExpiry,
      issuer: config.get().jwt.issuer,
      audience: config.get().jwt.audience,
    });
  }

  static generateRefreshToken(userId: string, sessionId: string): string {
    const payload = {
      sub: userId,
      sessionId,
      type: 'refresh',
      jti: crypto.randomUUID(),
      iat: Math.floor(Date.now() / 1000),
    };

    return jwt.sign(payload, this.SECRET, {
      algorithm: this.ALGORITHM,
      expiresIn: config.get().jwt.refreshTokenExpiry,
      issuer: config.get().jwt.issuer,
      audience: config.get().jwt.audience,
    });
  }

  static verifyToken(token: string): any {
    try {
      return jwt.verify(token, this.SECRET, {
        algorithms: [this.ALGORITHM],
        issuer: config.get().jwt.issuer,
        audience: config.get().jwt.audience,
        clockTolerance: 30, // 30 seconds clock tolerance
      });
    } catch (error) {
      if (error instanceof jwt.TokenExpiredError) {
        throw new TokenExpiredError();
      }
      if (error instanceof jwt.JsonWebTokenError) {
        throw new InvalidTokenError();
      }
      throw error;
    }
  }

  // Token blacklisting for logout and security
  static async blacklistToken(jti: string, expiresAt: Date): Promise<void> {
    // Store in cache/database for blacklist checking
    await redis.setex(`blacklist:${jti}`, Math.floor((expiresAt.getTime() - Date.now()) / 1000), '1');
  }

  static async isTokenBlacklisted(jti: string): Promise<boolean> {
    const result = await redis.get(`blacklist:${jti}`);
    return result !== null;
  }
}
```

### 3. Session Security

#### Secure Session Management

```typescript
// src/lib/security/session.ts
import { randomBytes } from 'crypto';
import { prisma } from '../db/prisma';

export class SessionSecurity {
  static readonly MAX_SESSIONS_PER_USER = 5;
  static readonly SESSION_TIMEOUT = 7 * 24 * 60 * 60 * 1000; // 7 days
  static readonly ACTIVITY_TIMEOUT = 30 * 60 * 1000; // 30 minutes

  static generateSessionId(): string {
    return randomBytes(32).toString('hex');
  }

  static async createSession(
    userId: string,
    userAgent?: string,
    ipAddress?: string
  ): Promise<Session> {
    // Check for too many active sessions
    const activeSessions = await prisma.session.count({
      where: {
        userId,
        isValid: true,
        expiresAt: { gt: new Date() },
      },
    });

    if (activeSessions >= this.MAX_SESSIONS_PER_USER) {
      // Remove oldest session
      const oldestSession = await prisma.session.findFirst({
        where: {
          userId,
          isValid: true,
        },
        orderBy: { lastActivityAt: 'asc' },
      });

      if (oldestSession) {
        await this.invalidateSession(oldestSession.id);
      }
    }

    const expiresAt = new Date(Date.now() + this.SESSION_TIMEOUT);
    
    return await prisma.session.create({
      data: {
        userId,
        userAgent: userAgent?.substring(0, 500), // Limit length
        ipAddress: this.sanitizeIpAddress(ipAddress),
        expiresAt,
        lastActivityAt: new Date(),
      },
    });
  }

  static async validateSession(sessionId: string): Promise<Session | null> {
    const session = await prisma.session.findUnique({
      where: { id: sessionId },
      include: { user: true },
    });

    if (!session || !session.isValid) {
      return null;
    }

    // Check expiration
    if (session.expiresAt < new Date()) {
      await this.invalidateSession(sessionId);
      return null;
    }

    // Check activity timeout
    const lastActivity = session.lastActivityAt.getTime();
    const now = Date.now();
    
    if (now - lastActivity > this.ACTIVITY_TIMEOUT) {
      await this.invalidateSession(sessionId);
      return null;
    }

    return session;
  }

  static async updateActivity(sessionId: string): Promise<void> {
    await prisma.session.update({
      where: { id: sessionId },
      data: { 
        lastActivityAt: new Date(),
        // Extend expiration on activity
        expiresAt: new Date(Date.now() + this.SESSION_TIMEOUT),
      },
    });
  }

  static async invalidateSession(sessionId: string): Promise<void> {
    await prisma.session.update({
      where: { id: sessionId },
      data: { isValid: false },
    });
  }

  static async invalidateAllUserSessions(
    userId: string,
    excludeSessionId?: string
  ): Promise<number> {
    const result = await prisma.session.updateMany({
      where: {
        userId,
        isValid: true,
        ...(excludeSessionId && { id: { not: excludeSessionId } }),
      },
      data: { isValid: false },
    });

    return result.count;
  }

  private static sanitizeIpAddress(ip?: string): string | null {
    if (!ip) return null;
    
    // Remove any potential malicious content
    const cleaned = ip.replace(/[^0-9a-fA-F:\.]/g, '').substring(0, 45);
    
    // Validate IPv4 or IPv6 format
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    
    if (ipv4Regex.test(cleaned) || ipv6Regex.test(cleaned)) {
      return cleaned;
    }
    
    return null;
  }
}
```

## Input Validation and Sanitization

### 1. Request Validation

```typescript
// src/lib/security/validation.ts
import { z } from 'zod';
import DOMPurify from 'isomorphic-dompurify';

export class InputValidator {
  // Email validation with additional security checks
  static readonly emailSchema = z
    .string()
    .email('Invalid email format')
    .max(255, 'Email too long')
    .toLowerCase()
    .refine((email) => {
      // Block disposable email domains
      const disposableDomains = [
        '10minutemail.com', 'tempmail.org', 'guerrillamail.com'
      ];
      const domain = email.split('@')[1];
      return !disposableDomains.includes(domain);
    }, 'Disposable email addresses are not allowed');

  // Username validation
  static readonly usernameSchema = z
    .string()
    .min(3, 'Username too short')
    .max(30, 'Username too long')
    .regex(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
    .refine((username) => {
      // Block reserved usernames
      const reserved = ['admin', 'root', 'system', 'api', 'www', 'mail'];
      return !reserved.includes(username.toLowerCase());
    }, 'Username is reserved');

  // Password validation
  static readonly passwordSchema = z
    .string()
    .min(8, 'Password too short')
    .max(128, 'Password too long')
    .refine((password) => {
      const validation = PasswordSecurity.validateStrength(password);
      return validation.isValid;
    }, 'Password does not meet security requirements');

  // Name validation
  static readonly nameSchema = z
    .string()
    .min(1, 'Name is required')
    .max(50, 'Name too long')
    .regex(/^[a-zA-Z\s'-]+$/, 'Name contains invalid characters')
    .transform((name) => this.sanitizeText(name));

  // Generic text sanitization
  static sanitizeText(text: string): string {
    // Remove HTML tags and encode entities
    const cleaned = DOMPurify.sanitize(text, { ALLOWED_TAGS: [] });
    
    // Normalize whitespace
    return cleaned.trim().replace(/\s+/g, ' ');
  }

  // URL validation
  static validateUrl(url: string, allowedDomains?: string[]): boolean {
    try {
      const urlObj = new URL(url);
      
      // Only allow HTTPS in production
      if (config.get().nodeEnv === 'production' && urlObj.protocol !== 'https:') {
        return false;
      }
      
      // Check allowed domains
      if (allowedDomains && !allowedDomains.includes(urlObj.hostname)) {
        return false;
      }
      
      return true;
    } catch {
      return false;
    }
  }

  // IP address validation and sanitization
  static sanitizeIpAddress(ip: string): string | null {
    // Handle X-Forwarded-For header format
    const cleanIp = ip.split(',')[0].trim();
    
    // IPv4 validation
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(cleanIp)) {
      const parts = cleanIp.split('.').map(Number);
      if (parts.every(part => part >= 0 && part <= 255)) {
        return cleanIp;
      }
    }
    
    // IPv6 validation (simplified)
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
    if (ipv6Regex.test(cleanIp)) {
      return cleanIp;
    }
    
    return null;
  }
}
```

### 2. SQL Injection Prevention

```typescript
// src/lib/security/database.ts
import { prisma } from '../db/prisma';

export class DatabaseSecurity {
  // Use parameterized queries (Prisma handles this automatically)
  static async safeFindUser(email: string): Promise<User | null> {
    // Prisma automatically prevents SQL injection
    return await prisma.user.findUnique({
      where: { email: email.toLowerCase().trim() },
    });
  }

  // Raw query safety (when needed)
  static async safeRawQuery(query: string, params: any[]): Promise<any> {
    // Validate parameters
    const sanitizedParams = params.map(param => {
      if (typeof param === 'string') {
        return param.replace(/['"\\]/g, ''); // Basic sanitization
      }
      return param;
    });

    return await prisma.$queryRawUnsafe(query, ...sanitizedParams);
  }

  // Database health check with timeout
  static async healthCheck(timeoutMs: number = 5000): Promise<boolean> {
    try {
      const promise = prisma.$queryRaw`SELECT 1`;
      const timeout = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Database timeout')), timeoutMs)
      );

      await Promise.race([promise, timeout]);
      return true;
    } catch (error) {
      logger.error('Database health check failed', { error });
      return false;
    }
  }
}
```

## Rate Limiting and DDoS Protection

### 1. Advanced Rate Limiting

```typescript
// src/lib/security/rate-limit.ts
import { Redis } from 'ioredis';

export class RateLimiter {
  private redis: Redis;

  constructor() {
    this.redis = new Redis(config.get().cache.redisUrl);
  }

  async checkLimit(
    identifier: string,
    windowMs: number,
    maxRequests: number,
    keyPrefix: string = 'rate_limit'
  ): Promise<{
    allowed: boolean;
    remaining: number;
    resetTime: number;
  }> {
    const key = `${keyPrefix}:${identifier}`;
    const now = Date.now();
    const windowStart = now - windowMs;

    // Use Redis sorted set for sliding window
    const pipeline = this.redis.pipeline();
    
    // Remove expired entries
    pipeline.zremrangebyscore(key, 0, windowStart);
    
    // Add current request
    pipeline.zadd(key, now, `${now}-${Math.random()}`);
    
    // Count requests in window
    pipeline.zcard(key);
    
    // Set expiration
    pipeline.expire(key, Math.ceil(windowMs / 1000));
    
    const results = await pipeline.exec();
    const count = results?.[2]?.[1] as number;

    const remaining = Math.max(0, maxRequests - count);
    const resetTime = now + windowMs;

    return {
      allowed: count <= maxRequests,
      remaining,
      resetTime,
    };
  }

  // IP-based rate limiting
  async checkIpLimit(
    ip: string,
    windowMs: number = 15 * 60 * 1000, // 15 minutes
    maxRequests: number = 100
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    return this.checkLimit(ip, windowMs, maxRequests, 'ip_limit');
  }

  // User-based rate limiting
  async checkUserLimit(
    userId: string,
    windowMs: number = 60 * 1000, // 1 minute
    maxRequests: number = 60
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    return this.checkLimit(userId, windowMs, maxRequests, 'user_limit');
  }

  // Endpoint-specific rate limiting
  async checkEndpointLimit(
    identifier: string,
    endpoint: string,
    windowMs: number,
    maxRequests: number
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    return this.checkLimit(
      `${identifier}:${endpoint}`,
      windowMs,
      maxRequests,
      'endpoint_limit'
    );
  }

  // Progressive delay for repeated violations
  async getProggressiveDelay(identifier: string): Promise<number> {
    const key = `progressive_delay:${identifier}`;
    const violations = await this.redis.incr(key);
    
    // Set expiration for violation counter (1 hour)
    await this.redis.expire(key, 3600);

    // Progressive delay: 1s, 2s, 4s, 8s, max 30s
    const delay = Math.min(Math.pow(2, violations - 1) * 1000, 30000);
    return delay;
  }
}

export const rateLimiter = new RateLimiter();
```

### 2. Request Throttling Middleware

```typescript
// src/lib/middleware/throttle.ts
import type { Context } from 'elysia';
import { rateLimiter } from '../security/rate-limit';
import { RateLimitExceededError } from '../errors';

export interface ThrottleOptions {
  windowMs: number;
  maxRequests: number;
  keyGenerator?: (ctx: Context) => string;
  onLimitReached?: (ctx: Context) => void;
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
}

export const throttle = (options: ThrottleOptions) => {
  return async (ctx: Context) => {
    const identifier = options.keyGenerator
      ? options.keyGenerator(ctx)
      : ctx.request.headers.get('x-forwarded-for') || 
        ctx.request.headers.get('x-real-ip') || 
        'unknown';

    const result = await rateLimiter.checkLimit(
      identifier,
      options.windowMs,
      options.maxRequests,
      'throttle'
    );

    // Set rate limit headers
    ctx.set.headers = {
      'X-RateLimit-Limit': options.maxRequests.toString(),
      'X-RateLimit-Remaining': result.remaining.toString(),
      'X-RateLimit-Reset': result.resetTime.toString(),
    };

    if (!result.allowed) {
      // Apply progressive delay for repeated violations
      const delay = await rateLimiter.getProggressiveDelay(identifier);
      
      if (delay > 0) {
        await new Promise(resolve => setTimeout(resolve, delay));
      }

      if (options.onLimitReached) {
        options.onLimitReached(ctx);
      }

      throw new RateLimitExceededError();
    }

    return ctx;
  };
};

// Pre-configured throttlers for different endpoints
export const authThrottle = throttle({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 5,
  keyGenerator: (ctx) => {
    const body = ctx.body as any;
    return body?.email || 'unknown';
  },
});

export const generalThrottle = throttle({
  windowMs: 15 * 60 * 1000, // 15 minutes
  maxRequests: 100,
});

export const strictThrottle = throttle({
  windowMs: 60 * 1000, // 1 minute
  maxRequests: 10,
});
```

## CSRF Protection

### 1. CSRF Token Implementation

```typescript
// src/lib/security/csrf.ts
import crypto from 'crypto';
import { Redis } from 'ioredis';

export class CSRFProtection {
  private redis: Redis;
  private readonly TOKEN_LENGTH = 32;
  private readonly TOKEN_EXPIRY = 3600; // 1 hour

  constructor() {
    this.redis = new Redis(config.get().cache.redisUrl);
  }

  generateToken(sessionId: string): string {
    const token = crypto.randomBytes(this.TOKEN_LENGTH).toString('hex');
    
    // Store token with session association
    this.redis.setex(`csrf:${token}`, this.TOKEN_EXPIRY, sessionId);
    
    return token;
  }

  async validateToken(token: string, sessionId: string): Promise<boolean> {
    const storedSessionId = await this.redis.get(`csrf:${token}`);
    
    if (storedSessionId !== sessionId) {
      return false;
    }

    // Remove token after use (one-time use)
    await this.redis.del(`csrf:${token}`);
    
    return true;
  }

  // Double submit cookie pattern
  generateDoubleSubmitToken(): string {
    return crypto.randomBytes(this.TOKEN_LENGTH).toString('hex');
  }

  validateDoubleSubmitToken(cookieToken: string, headerToken: string): boolean {
    if (!cookieToken || !headerToken) {
      return false;
    }

    // Constant-time comparison to prevent timing attacks
    return crypto.timingSafeEqual(
      Buffer.from(cookieToken, 'hex'),
      Buffer.from(headerToken, 'hex')
    );
  }
}

export const csrfProtection = new CSRFProtection();
```

### 2. CSRF Middleware

```typescript
// src/lib/middleware/csrf.ts
import type { Context } from 'elysia';
import { csrfProtection } from '../security/csrf';
import { CSRFError } from '../errors';

export const csrfMiddleware = async (ctx: Context) => {
  // Skip CSRF for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(ctx.request.method)) {
    return ctx;
  }

  // Skip CSRF for API requests with Bearer token
  const authorization = ctx.request.headers.get('authorization');
  if (authorization?.startsWith('Bearer ')) {
    return ctx;
  }

  const cookieToken = ctx.cookie?.csrf_token;
  const headerToken = ctx.request.headers.get('x-csrf-token');

  if (!csrfProtection.validateDoubleSubmitToken(cookieToken, headerToken)) {
    throw new CSRFError();
  }

  return ctx;
};

// Generate CSRF token endpoint
export const generateCSRFToken = (ctx: Context) => {
  const token = csrfProtection.generateDoubleSubmitToken();
  
  // Set secure cookie
  ctx.set.cookie = {
    csrf_token: {
      value: token,
      httpOnly: true,
      secure: config.get().nodeEnv === 'production',
      sameSite: 'strict',
      maxAge: 3600, // 1 hour
    },
  };

  return { csrfToken: token };
};
```

## Content Security Policy (CSP)

### 1. CSP Implementation

```typescript
// src/lib/security/csp.ts
export class ContentSecurityPolicy {
  static generateNonce(): string {
    return crypto.randomBytes(16).toString('base64');
  }

  static generateCSPHeader(nonce?: string): string {
    const directives = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-eval'", // Unsafe-eval needed for some frameworks
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: https://cdn.tamatar.dev",
      "connect-src 'self' https://api.tamatar.dev",
      "frame-src 'none'",
      "object-src 'none'",
      "base-uri 'self'",
      "form-action 'self'",
      "frame-ancestors 'none'",
      "block-all-mixed-content",
      "upgrade-insecure-requests"
    ];

    if (nonce) {
      directives[1] = `script-src 'self' 'nonce-${nonce}'`;
    }

    return directives.join('; ');
  }
}
```

## Security Headers

### 1. Security Headers Middleware

```typescript
// src/lib/middleware/security-headers.ts
import type { Context } from 'elysia';
import { ContentSecurityPolicy } from '../security/csp';

export const securityHeaders = (ctx: Context) => {
  const nonce = ContentSecurityPolicy.generateNonce();
  
  ctx.set.headers = {
    // Content Security Policy
    'Content-Security-Policy': ContentSecurityPolicy.generateCSPHeader(nonce),
    
    // Prevent MIME type sniffing
    'X-Content-Type-Options': 'nosniff',
    
    // XSS Protection
    'X-XSS-Protection': '1; mode=block',
    
    // Frame Options
    'X-Frame-Options': 'DENY',
    
    // HSTS (HTTP Strict Transport Security)
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    
    // Referrer Policy
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    
    // Feature Policy
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    
    // Remove server information
    'Server': 'Tamatar-Auth',
    
    // Cache control for sensitive endpoints
    'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
    'Pragma': 'no-cache',
    'Expires': '0',
  };

  // Store nonce for use in templates
  ctx.nonce = nonce;

  return ctx;
};
```

## Encryption and Data Protection

### 1. Data Encryption

```typescript
// src/lib/security/encryption.ts
import crypto from 'crypto';

export class DataEncryption {
  private static readonly ALGORITHM = 'aes-256-gcm';
  private static readonly KEY_LENGTH = 32;
  private static readonly IV_LENGTH = 16;
  private static readonly TAG_LENGTH = 16;
  
  private static getKey(): Buffer {
    const key = config.get().encryption?.key || process.env.ENCRYPTION_KEY;
    if (!key) {
      throw new Error('Encryption key not configured');
    }
    return crypto.scryptSync(key, 'salt', this.KEY_LENGTH);
  }

  static encrypt(text: string): string {
    const key = this.getKey();
    const iv = crypto.randomBytes(this.IV_LENGTH);
    
    const cipher = crypto.createCipher(this.ALGORITHM, key);
    cipher.setAAD(Buffer.from('tamatar-auth'));
    
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    // Combine iv + encrypted + tag
    return iv.toString('hex') + ':' + encrypted + ':' + tag.toString('hex');
  }

  static decrypt(encryptedData: string): string {
    const parts = encryptedData.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }

    const key = this.getKey();
    const iv = Buffer.from(parts[0], 'hex');
    const encrypted = parts[1];
    const tag = Buffer.from(parts[2], 'hex');
    
    const decipher = crypto.createDecipher(this.ALGORITHM, key);
    decipher.setAAD(Buffer.from('tamatar-auth'));
    decipher.setAuthTag(tag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }

  // Hash sensitive data that doesn't need to be reversed
  static hash(data: string): string {
    return crypto.createHash('sha256').update(data).digest('hex');
  }

  // Secure random token generation
  static generateToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  // Time-safe string comparison
  static safeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }
    
    return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
  }
}
```

## Audit Logging and Monitoring

### 1. Security Event Logging

```typescript
// src/lib/security/audit.ts
import { prisma } from '../db/prisma';
import { logger } from '../utils/logger';

export enum SecurityEventType {
  LOGIN_SUCCESS = 'login_success',
  LOGIN_FAILURE = 'login_failure',
  PASSWORD_CHANGE = 'password_change',
  EMAIL_CHANGE = 'email_change',
  ACCOUNT_LOCKED = 'account_locked',
  SUSPICIOUS_ACTIVITY = 'suspicious_activity',
  TOKEN_REFRESH = 'token_refresh',
  SESSION_CREATED = 'session_created',
  SESSION_INVALIDATED = 'session_invalidated',
  RATE_LIMIT_EXCEEDED = 'rate_limit_exceeded',
  CSRF_VIOLATION = 'csrf_violation',
  INVALID_TOKEN = 'invalid_token',
}

export class SecurityAudit {
  static async logEvent(
    eventType: SecurityEventType,
    userId?: string,
    metadata?: Record<string, any>,
    ipAddress?: string,
    userAgent?: string
  ): Promise<void> {
    try {
      // Log to database
      await prisma.securityEvent.create({
        data: {
          eventType,
          userId,
          metadata,
          ipAddress,
          userAgent,
          timestamp: new Date(),
        },
      });

      // Log to application logger
      logger.warn('Security event', {
        eventType,
        userId,
        metadata,
        ipAddress,
        userAgent,
      });

      // Send alerts for critical events
      if (this.isCriticalEvent(eventType)) {
        await this.sendSecurityAlert(eventType, userId, metadata);
      }
    } catch (error) {
      logger.error('Failed to log security event', { error, eventType, userId });
    }
  }

  private static isCriticalEvent(eventType: SecurityEventType): boolean {
    const criticalEvents = [
      SecurityEventType.ACCOUNT_LOCKED,
      SecurityEventType.SUSPICIOUS_ACTIVITY,
      SecurityEventType.RATE_LIMIT_EXCEEDED,
      SecurityEventType.CSRF_VIOLATION,
    ];
    
    return criticalEvents.includes(eventType);
  }

  private static async sendSecurityAlert(
    eventType: SecurityEventType,
    userId?: string,
    metadata?: Record<string, any>
  ): Promise<void> {
    // Implementation depends on alerting system (email, Slack, PagerDuty, etc.)
    logger.error('SECURITY ALERT', { eventType, userId, metadata });
    
    // Could integrate with external alerting services
    // await slackNotifier.sendAlert(...);
    // await emailNotifier.sendSecurityAlert(...);
  }

  static async getSecurityMetrics(startDate: Date, endDate: Date) {
    const events = await prisma.securityEvent.groupBy({
      by: ['eventType'],
      where: {
        timestamp: {
          gte: startDate,
          lte: endDate,
        },
      },
      _count: true,
    });

    return events.reduce((acc, event) => {
      acc[event.eventType] = event._count;
      return acc;
    }, {} as Record<string, number>);
  }

  static async detectAnomalies(userId: string): Promise<boolean> {
    const recentEvents = await prisma.securityEvent.findMany({
      where: {
        userId,
        timestamp: {
          gte: new Date(Date.now() - 24 * 60 * 60 * 1000), // Last 24 hours
        },
      },
      orderBy: { timestamp: 'desc' },
    });

    // Check for suspicious patterns
    const failedLogins = recentEvents.filter(e => 
      e.eventType === SecurityEventType.LOGIN_FAILURE
    ).length;

    const differentIps = new Set(
      recentEvents.map(e => e.ipAddress).filter(Boolean)
    ).size;

    // Flag as suspicious if many failed logins or logins from many different IPs
    return failedLogins > 10 || differentIps > 5;
  }
}
```

## Security Testing

### 1. Security Test Utilities

```typescript
// src/lib/security/testing.ts
import { PasswordSecurity } from './password';
import { JWTSecurity } from './jwt';
import { rateLimiter } from './rate-limit';

export class SecurityTesting {
  static async testPasswordSecurity(): Promise<void> {
    console.log('Testing password security...');
    
    // Test weak passwords
    const weakPasswords = ['password', '123456', 'qwerty'];
    for (const password of weakPasswords) {
      const result = PasswordSecurity.validateStrength(password);
      console.assert(!result.isValid, `Weak password should be rejected: ${password}`);
    }

    // Test strong password
    const strongPassword = 'StrongP@ssw0rd123!';
    const strongResult = PasswordSecurity.validateStrength(strongPassword);
    console.assert(strongResult.isValid, 'Strong password should be accepted');

    console.log('Password security tests passed');
  }

  static async testJWTSecurity(): Promise<void> {
    console.log('Testing JWT security...');
    
    // Test token generation and verification
    const payload = { sub: 'test-user', email: 'test@example.com' };
    const token = JWTSecurity.generateAccessToken(payload);
    
    try {
      const decoded = JWTSecurity.verifyToken(token);
      console.assert(decoded.sub === payload.sub, 'Token should decode correctly');
    } catch (error) {
      console.error('JWT verification failed', error);
    }

    // Test invalid token
    try {
      JWTSecurity.verifyToken('invalid.token.here');
      console.assert(false, 'Invalid token should throw error');
    } catch (error) {
      // Expected
    }

    console.log('JWT security tests passed');
  }

  static async testRateLimiting(): Promise<void> {
    console.log('Testing rate limiting...');
    
    const identifier = 'test-user';
    const windowMs = 1000; // 1 second
    const maxRequests = 3;

    // Make requests up to limit
    for (let i = 0; i < maxRequests; i++) {
      const result = await rateLimiter.checkLimit(identifier, windowMs, maxRequests);
      console.assert(result.allowed, `Request ${i + 1} should be allowed`);
    }

    // Exceed limit
    const exceededResult = await rateLimiter.checkLimit(identifier, windowMs, maxRequests);
    console.assert(!exceededResult.allowed, 'Request exceeding limit should be blocked');

    console.log('Rate limiting tests passed');
  }

  static async runAllTests(): Promise<void> {
    await this.testPasswordSecurity();
    await this.testJWTSecurity();
    await this.testRateLimiting();
    console.log('All security tests passed');
  }
}
```

## Security Checklist

### 1. Pre-deployment Security Checklist

- [ ] Strong password requirements enforced
- [ ] JWT tokens properly configured with short expiration
- [ ] Rate limiting implemented on all endpoints
- [ ] CSRF protection enabled for web requests
- [ ] Security headers configured
- [ ] Input validation and sanitization implemented
- [ ] SQL injection prevention verified
- [ ] Sensitive data encrypted at rest
- [ ] Audit logging implemented
- [ ] Error handling doesn't leak sensitive information
- [ ] Dependencies updated and vulnerability scanned
- [ ] Security tests passing
- [ ] HTTPS enforced in production
- [ ] Database connections secured
- [ ] Environment variables properly protected

### 2. Operational Security

- [ ] Regular security audits scheduled
- [ ] Monitoring and alerting configured
- [ ] Incident response plan documented
- [ ] Backup and recovery procedures tested
- [ ] Access controls reviewed
- [ ] Security training for team members
- [ ] Vulnerability disclosure process documented
- [ ] Regular penetration testing scheduled

This comprehensive security implementation provides multiple layers of protection for the Tamatar Auth microservice, following industry best practices and security standards.
