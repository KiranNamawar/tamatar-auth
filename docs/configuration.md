# Configuration Guide

## Overview

This guide covers all configuration options for the Tamatar Auth microservice, including environment variables, application settings, and deployment configurations.

## Environment Variables

### Required Variables

```bash
# Database Configuration
DATABASE_URL="postgresql://username:password@host:port/database"

# JWT Configuration  
JWT_SECRET="your-256-bit-secret-key-here"

# Email Service
RESEND_API_KEY="re_your_resend_api_key"
```

### Complete Environment Configuration

```bash
# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
DATABASE_URL="postgresql://username:password@localhost:5432/tamatar_auth"
DATABASE_POOL_SIZE=10
DATABASE_CONNECTION_TIMEOUT=5000
DATABASE_QUERY_TIMEOUT=10000

# =============================================================================
# JWT & AUTHENTICATION CONFIGURATION
# =============================================================================
JWT_SECRET="your-super-secure-256-bit-secret-key-here"
JWT_ACCESS_TOKEN_EXPIRY="15m"
JWT_REFRESH_TOKEN_EXPIRY="7d"
JWT_ISSUER="tamatar-auth"
JWT_AUDIENCE="tamatar-services"

# =============================================================================
# SESSION CONFIGURATION
# =============================================================================
SESSION_MAX_AGE="7d"
SESSION_CLEANUP_INTERVAL="24h"
MAX_SESSIONS_PER_USER=5

# =============================================================================
# EMAIL SERVICE CONFIGURATION
# =============================================================================
RESEND_API_KEY="re_your_resend_api_key"
FROM_EMAIL="Tamatar Auth <auth@email.tamatar.dev>"
REPLY_TO_EMAIL="support@tamatar.dev"

# Email Features
EMAIL_VERIFICATION_ENABLED=true
PASSWORD_RESET_ENABLED=true
LOGIN_NOTIFICATIONS_ENABLED=false

# Email Rate Limiting
EMAIL_RATE_LIMIT_PER_HOUR=5
EMAIL_RATE_LIMIT_PER_DAY=20

# =============================================================================
# OAUTH CONFIGURATION
# =============================================================================
# Google OAuth
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
GOOGLE_REDIRECT_URI="https://auth.tamatar.dev/oauth/google/callback"

# OAuth Features
OAUTH_GOOGLE_ENABLED=true
OAUTH_AUTO_LINK_ACCOUNTS=true

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================
# Password Requirements
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SYMBOLS=true

# Account Security
ACCOUNT_LOCKOUT_ENABLED=true
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION="30m"
FAILED_ATTEMPT_WINDOW="15m"

# CSRF Protection
CSRF_PROTECTION_ENABLED=true
CSRF_TOKEN_EXPIRY="1h"

# =============================================================================
# RATE LIMITING CONFIGURATION
# =============================================================================
# General API Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW="15m"
RATE_LIMIT_MAX_REQUESTS=100

# Authentication Endpoints
LOGIN_RATE_LIMIT_MAX=5
LOGIN_RATE_LIMIT_WINDOW="15m"
REGISTER_RATE_LIMIT_MAX=3
REGISTER_RATE_LIMIT_WINDOW="1h"

# =============================================================================
# APPLICATION CONFIGURATION
# =============================================================================
NODE_ENV="production"
PORT=3000
HOST="0.0.0.0"

# Logging
LOG_LEVEL="info"
LOG_FORMAT="json"
LOG_FILE_ENABLED=true
LOG_FILE_PATH="./logs"

# =============================================================================
# CORS CONFIGURATION
# =============================================================================
CORS_ENABLED=true
CORS_ORIGIN="https://app.tamatar.dev,https://admin.tamatar.dev"
CORS_CREDENTIALS=true
CORS_MAX_AGE="86400"

# =============================================================================
# FRONTEND URLS
# =============================================================================
FRONTEND_URL="https://app.tamatar.dev"
ADMIN_URL="https://admin.tamatar.dev"
AUTH_URL="https://auth.tamatar.dev"

# =============================================================================
# MONITORING & HEALTH CHECKS
# =============================================================================
HEALTH_CHECK_ENABLED=true
METRICS_ENABLED=true
METRICS_PORT=9090

# External Monitoring
SENTRY_DSN="https://your-sentry-dsn"
SENTRY_ENVIRONMENT="production"

# =============================================================================
# FEATURE FLAGS
# =============================================================================
FEATURE_REGISTRATION_ENABLED=true
FEATURE_OAUTH_ENABLED=true
FEATURE_PASSWORD_RESET_ENABLED=true
FEATURE_ADMIN_API_ENABLED=false

# =============================================================================
# CACHE CONFIGURATION
# =============================================================================
REDIS_URL="redis://localhost:6379"
CACHE_TTL="1h"
CACHE_PREFIX="tamatar:auth:"

# =============================================================================
# FILE UPLOAD CONFIGURATION
# =============================================================================
UPLOAD_MAX_SIZE="5MB"
UPLOAD_ALLOWED_TYPES="image/jpeg,image/png,image/webp"
AVATAR_STORAGE_PROVIDER="s3"
S3_BUCKET="tamatar-avatars"
S3_REGION="us-east-1"
S3_ACCESS_KEY="your-s3-access-key"
S3_SECRET_KEY="your-s3-secret-key"
```

## Configuration Management

### Environment-Specific Configurations

#### Development (.env.development)

```bash
NODE_ENV="development"
DATABASE_URL="postgresql://dev_user:dev_pass@localhost:5432/tamatar_auth_dev"
JWT_SECRET="dev-secret-key-not-for-production"
FRONTEND_URL="http://localhost:3000"
LOG_LEVEL="debug"
EMAIL_VERIFICATION_ENABLED=false  # Skip email verification in dev
RATE_LIMIT_ENABLED=false          # Disable rate limiting in dev
```

#### Testing (.env.test)

```bash
NODE_ENV="test"
DATABASE_URL="postgresql://test_user:test_pass@localhost:5432/tamatar_auth_test"
JWT_SECRET="test-secret-key"
EMAIL_VERIFICATION_ENABLED=false
RATE_LIMIT_ENABLED=false
LOG_LEVEL="error"                 # Reduce noise in tests
```

#### Production (.env.production)

```bash
NODE_ENV="production"
DATABASE_URL="${DATABASE_URL}"    # Use runtime environment variable
JWT_SECRET="${JWT_SECRET}"
LOG_LEVEL="info"
RATE_LIMIT_ENABLED=true
EMAIL_VERIFICATION_ENABLED=true
SENTRY_DSN="${SENTRY_DSN}"
```

### Configuration Service

```typescript
// src/lib/config/index.ts
import { z } from 'zod';

// Configuration schema with validation
const configSchema = z.object({
  // Environment
  nodeEnv: z.enum(['development', 'test', 'production']).default('development'),
  port: z.coerce.number().default(3000),
  host: z.string().default('localhost'),

  // Database
  database: z.object({
    url: z.string().url(),
    poolSize: z.coerce.number().default(10),
    connectionTimeout: z.coerce.number().default(5000),
    queryTimeout: z.coerce.number().default(10000),
  }),

  // JWT
  jwt: z.object({
    secret: z.string().min(32),
    accessTokenExpiry: z.string().default('15m'),
    refreshTokenExpiry: z.string().default('7d'),
    issuer: z.string().default('tamatar-auth'),
    audience: z.string().default('tamatar-services'),
  }),

  // Email
  email: z.object({
    resendApiKey: z.string(),
    fromEmail: z.string().email(),
    replyToEmail: z.string().email().optional(),
    verificationEnabled: z.boolean().default(true),
    passwordResetEnabled: z.boolean().default(true),
    loginNotificationsEnabled: z.boolean().default(false),
    rateLimits: z.object({
      perHour: z.coerce.number().default(5),
      perDay: z.coerce.number().default(20),
    }),
  }),

  // OAuth
  oauth: z.object({
    google: z.object({
      enabled: z.boolean().default(false),
      clientId: z.string().optional(),
      clientSecret: z.string().optional(),
      redirectUri: z.string().url().optional(),
    }),
    autoLinkAccounts: z.boolean().default(true),
  }),

  // Security
  security: z.object({
    password: z.object({
      minLength: z.coerce.number().default(8),
      requireUppercase: z.boolean().default(true),
      requireLowercase: z.boolean().default(true),
      requireNumbers: z.boolean().default(true),
      requireSymbols: z.boolean().default(true),
    }),
    accountLockout: z.object({
      enabled: z.boolean().default(true),
      maxAttempts: z.coerce.number().default(5),
      lockoutDuration: z.string().default('30m'),
      attemptWindow: z.string().default('15m'),
    }),
    csrf: z.object({
      enabled: z.boolean().default(true),
      tokenExpiry: z.string().default('1h'),
    }),
  }),

  // Rate Limiting
  rateLimiting: z.object({
    enabled: z.boolean().default(true),
    window: z.string().default('15m'),
    maxRequests: z.coerce.number().default(100),
    auth: z.object({
      login: z.object({
        max: z.coerce.number().default(5),
        window: z.string().default('15m'),
      }),
      register: z.object({
        max: z.coerce.number().default(3),
        window: z.string().default('1h'),
      }),
    }),
  }),

  // CORS
  cors: z.object({
    enabled: z.boolean().default(true),
    origin: z.union([z.string(), z.array(z.string())]).default('*'),
    credentials: z.boolean().default(true),
    maxAge: z.coerce.number().default(86400),
  }),

  // URLs
  urls: z.object({
    frontend: z.string().url(),
    admin: z.string().url().optional(),
    auth: z.string().url(),
  }),

  // Logging
  logging: z.object({
    level: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    format: z.enum(['json', 'simple']).default('json'),
    fileEnabled: z.boolean().default(true),
    filePath: z.string().default('./logs'),
  }),

  // Monitoring
  monitoring: z.object({
    healthCheckEnabled: z.boolean().default(true),
    metricsEnabled: z.boolean().default(true),
    metricsPort: z.coerce.number().default(9090),
    sentry: z.object({
      dsn: z.string().optional(),
      environment: z.string().optional(),
    }),
  }),

  // Features
  features: z.object({
    registrationEnabled: z.boolean().default(true),
    oauthEnabled: z.boolean().default(true),
    passwordResetEnabled: z.boolean().default(true),
    adminApiEnabled: z.boolean().default(false),
  }),

  // Cache
  cache: z.object({
    redisUrl: z.string().optional(),
    ttl: z.string().default('1h'),
    prefix: z.string().default('tamatar:auth:'),
  }),

  // File Upload
  upload: z.object({
    maxSize: z.string().default('5MB'),
    allowedTypes: z.string().default('image/jpeg,image/png,image/webp'),
    storageProvider: z.enum(['local', 's3']).default('local'),
    s3: z.object({
      bucket: z.string().optional(),
      region: z.string().optional(),
      accessKey: z.string().optional(),
      secretKey: z.string().optional(),
    }),
  }),
});

export type Config = z.infer<typeof configSchema>;

class ConfigService {
  private config: Config;

  constructor() {
    this.config = this.loadConfig();
  }

  private loadConfig(): Config {
    const rawConfig = {
      nodeEnv: process.env.NODE_ENV,
      port: process.env.PORT,
      host: process.env.HOST,

      database: {
        url: process.env.DATABASE_URL,
        poolSize: process.env.DATABASE_POOL_SIZE,
        connectionTimeout: process.env.DATABASE_CONNECTION_TIMEOUT,
        queryTimeout: process.env.DATABASE_QUERY_TIMEOUT,
      },

      jwt: {
        secret: process.env.JWT_SECRET,
        accessTokenExpiry: process.env.JWT_ACCESS_TOKEN_EXPIRY,
        refreshTokenExpiry: process.env.JWT_REFRESH_TOKEN_EXPIRY,
        issuer: process.env.JWT_ISSUER,
        audience: process.env.JWT_AUDIENCE,
      },

      email: {
        resendApiKey: process.env.RESEND_API_KEY,
        fromEmail: process.env.FROM_EMAIL,
        replyToEmail: process.env.REPLY_TO_EMAIL,
        verificationEnabled: process.env.EMAIL_VERIFICATION_ENABLED !== 'false',
        passwordResetEnabled: process.env.PASSWORD_RESET_ENABLED !== 'false',
        loginNotificationsEnabled: process.env.LOGIN_NOTIFICATIONS_ENABLED === 'true',
        rateLimits: {
          perHour: process.env.EMAIL_RATE_LIMIT_PER_HOUR,
          perDay: process.env.EMAIL_RATE_LIMIT_PER_DAY,
        },
      },

      oauth: {
        google: {
          enabled: process.env.OAUTH_GOOGLE_ENABLED === 'true',
          clientId: process.env.GOOGLE_CLIENT_ID,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          redirectUri: process.env.GOOGLE_REDIRECT_URI,
        },
        autoLinkAccounts: process.env.OAUTH_AUTO_LINK_ACCOUNTS !== 'false',
      },

      security: {
        password: {
          minLength: process.env.PASSWORD_MIN_LENGTH,
          requireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE !== 'false',
          requireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE !== 'false',
          requireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS !== 'false',
          requireSymbols: process.env.PASSWORD_REQUIRE_SYMBOLS !== 'false',
        },
        accountLockout: {
          enabled: process.env.ACCOUNT_LOCKOUT_ENABLED !== 'false',
          maxAttempts: process.env.MAX_LOGIN_ATTEMPTS,
          lockoutDuration: process.env.LOCKOUT_DURATION,
          attemptWindow: process.env.FAILED_ATTEMPT_WINDOW,
        },
        csrf: {
          enabled: process.env.CSRF_PROTECTION_ENABLED !== 'false',
          tokenExpiry: process.env.CSRF_TOKEN_EXPIRY,
        },
      },

      rateLimiting: {
        enabled: process.env.RATE_LIMIT_ENABLED !== 'false',
        window: process.env.RATE_LIMIT_WINDOW,
        maxRequests: process.env.RATE_LIMIT_MAX_REQUESTS,
        auth: {
          login: {
            max: process.env.LOGIN_RATE_LIMIT_MAX,
            window: process.env.LOGIN_RATE_LIMIT_WINDOW,
          },
          register: {
            max: process.env.REGISTER_RATE_LIMIT_MAX,
            window: process.env.REGISTER_RATE_LIMIT_WINDOW,
          },
        },
      },

      cors: {
        enabled: process.env.CORS_ENABLED !== 'false',
        origin: process.env.CORS_ORIGIN?.split(',') || '*',
        credentials: process.env.CORS_CREDENTIALS !== 'false',
        maxAge: process.env.CORS_MAX_AGE,
      },

      urls: {
        frontend: process.env.FRONTEND_URL,
        admin: process.env.ADMIN_URL,
        auth: process.env.AUTH_URL,
      },

      logging: {
        level: process.env.LOG_LEVEL,
        format: process.env.LOG_FORMAT,
        fileEnabled: process.env.LOG_FILE_ENABLED !== 'false',
        filePath: process.env.LOG_FILE_PATH,
      },

      monitoring: {
        healthCheckEnabled: process.env.HEALTH_CHECK_ENABLED !== 'false',
        metricsEnabled: process.env.METRICS_ENABLED !== 'false',
        metricsPort: process.env.METRICS_PORT,
        sentry: {
          dsn: process.env.SENTRY_DSN,
          environment: process.env.SENTRY_ENVIRONMENT,
        },
      },

      features: {
        registrationEnabled: process.env.FEATURE_REGISTRATION_ENABLED !== 'false',
        oauthEnabled: process.env.FEATURE_OAUTH_ENABLED !== 'false',
        passwordResetEnabled: process.env.FEATURE_PASSWORD_RESET_ENABLED !== 'false',
        adminApiEnabled: process.env.FEATURE_ADMIN_API_ENABLED === 'true',
      },

      cache: {
        redisUrl: process.env.REDIS_URL,
        ttl: process.env.CACHE_TTL,
        prefix: process.env.CACHE_PREFIX,
      },

      upload: {
        maxSize: process.env.UPLOAD_MAX_SIZE,
        allowedTypes: process.env.UPLOAD_ALLOWED_TYPES,
        storageProvider: process.env.AVATAR_STORAGE_PROVIDER,
        s3: {
          bucket: process.env.S3_BUCKET,
          region: process.env.S3_REGION,
          accessKey: process.env.S3_ACCESS_KEY,
          secretKey: process.env.S3_SECRET_KEY,
        },
      },
    };

    try {
      return configSchema.parse(rawConfig);
    } catch (error) {
      console.error('Configuration validation failed:', error);
      process.exit(1);
    }
  }

  get(): Config {
    return this.config;
  }

  isDevelopment(): boolean {
    return this.config.nodeEnv === 'development';
  }

  isProduction(): boolean {
    return this.config.nodeEnv === 'production';
  }

  isTest(): boolean {
    return this.config.nodeEnv === 'test';
  }
}

export const config = new ConfigService();
```

## Doppler Configuration

### Project Setup

```bash
# Install Doppler CLI
curl -Ls https://cli.doppler.com/install.sh | sh

# Login to Doppler
doppler login

# Create project
doppler projects create tamatar-auth

# Setup environments
doppler environments create development
doppler environments create staging  
doppler environments create production

# Set current project and environment
doppler setup --project tamatar-auth --config development
```

### Doppler Secrets Management

```bash
# Set secrets for development
doppler secrets set DATABASE_URL="postgresql://dev_user:dev_pass@localhost:5432/tamatar_auth_dev"
doppler secrets set JWT_SECRET="development-jwt-secret-key"
doppler secrets set RESEND_API_KEY="re_development_key"

# Set secrets for production
doppler configure set project tamatar-auth config production
doppler secrets set DATABASE_URL="postgresql://prod_user:prod_pass@prod-host:5432/tamatar_auth"
doppler secrets set JWT_SECRET="$(openssl rand -base64 32)"
doppler secrets set RESEND_API_KEY="re_production_key"

# Run application with Doppler
doppler run -- bun run start
```

### Doppler Configuration File

```yaml
# .doppler.yaml
setup:
  project: tamatar-auth
  config: development

environments:
  development:
    config: development
  staging:
    config: staging
  production:
    config: production
```

## Docker Configuration

### Dockerfile

```dockerfile
# Use Bun base image
FROM oven/bun:1-alpine AS base

# Set working directory
WORKDIR /app

# Install dependencies
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Copy application code
COPY . .

# Generate Prisma client
RUN bunx prisma generate

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Run application
CMD ["bun", "run", "start"]
```

### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_USER: ${POSTGRES_USER:-tamatar}
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-password}
      POSTGRES_DB: ${POSTGRES_DB:-tamatar_auth}
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U $${POSTGRES_USER} -d $${POSTGRES_DB}"]
      interval: 10s
      timeout: 5s
      retries: 5

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

  auth-service:
    build: .
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: "postgresql://${POSTGRES_USER:-tamatar}:${POSTGRES_PASSWORD:-password}@postgres:5432/${POSTGRES_DB:-tamatar_auth}"
      REDIS_URL: "redis://redis:6379"
      NODE_ENV: production
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

volumes:
  postgres_data:
  redis_data:
```

## Kubernetes Configuration

### ConfigMap

```yaml
# k8s/configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: tamatar-auth-config
  namespace: tamatar
data:
  NODE_ENV: "production"
  PORT: "3000"
  HOST: "0.0.0.0"
  JWT_ISSUER: "tamatar-auth"
  JWT_AUDIENCE: "tamatar-services"
  JWT_ACCESS_TOKEN_EXPIRY: "15m"
  JWT_REFRESH_TOKEN_EXPIRY: "7d"
  EMAIL_VERIFICATION_ENABLED: "true"
  PASSWORD_RESET_ENABLED: "true"
  RATE_LIMIT_ENABLED: "true"
  CORS_ENABLED: "true"
  HEALTH_CHECK_ENABLED: "true"
  METRICS_ENABLED: "true"
  LOG_LEVEL: "info"
  LOG_FORMAT: "json"
```

### Secret

```yaml
# k8s/secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: tamatar-auth-secrets
  namespace: tamatar
type: Opaque
data:
  DATABASE_URL: <base64-encoded-database-url>
  JWT_SECRET: <base64-encoded-jwt-secret>
  RESEND_API_KEY: <base64-encoded-resend-key>
  GOOGLE_CLIENT_SECRET: <base64-encoded-google-secret>
```

### Deployment

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tamatar-auth
  namespace: tamatar
spec:
  replicas: 3
  selector:
    matchLabels:
      app: tamatar-auth
  template:
    metadata:
      labels:
        app: tamatar-auth
    spec:
      containers:
      - name: auth-service
        image: tamatar/auth:latest
        ports:
        - containerPort: 3000
        envFrom:
        - configMapRef:
            name: tamatar-auth-config
        - secretRef:
            name: tamatar-auth-secrets
        livenessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /health
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          requests:
            memory: "256Mi"
            cpu: "250m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

## Configuration Validation

### Startup Validation

```typescript
// src/lib/config/validator.ts
import { config } from './index';
import { logger } from '../utils/logger';

export class ConfigValidator {
  static validate(): void {
    const cfg = config.get();
    const errors: string[] = [];

    // Validate required database connection
    if (!cfg.database.url) {
      errors.push('DATABASE_URL is required');
    }

    // Validate JWT secret strength
    if (cfg.jwt.secret.length < 32) {
      errors.push('JWT_SECRET must be at least 32 characters');
    }

    // Validate email configuration
    if (cfg.email.verificationEnabled && !cfg.email.resendApiKey) {
      errors.push('RESEND_API_KEY is required when email verification is enabled');
    }

    // Validate OAuth configuration
    if (cfg.oauth.google.enabled) {
      if (!cfg.oauth.google.clientId || !cfg.oauth.google.clientSecret) {
        errors.push('Google OAuth requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET');
      }
    }

    // Validate production settings
    if (cfg.nodeEnv === 'production') {
      if (cfg.jwt.secret === 'development-secret') {
        errors.push('Development JWT secret cannot be used in production');
      }
      
      if (!cfg.monitoring.sentry.dsn) {
        logger.warn('Sentry DSN not configured for production');
      }
    }

    if (errors.length > 0) {
      logger.error('Configuration validation failed', { errors });
      throw new Error(`Configuration errors: ${errors.join(', ')}`);
    }

    logger.info('Configuration validated successfully');
  }

  static logConfiguration(): void {
    const cfg = config.get();
    
    // Log safe configuration (without secrets)
    const safeConfig = {
      nodeEnv: cfg.nodeEnv,
      port: cfg.port,
      features: cfg.features,
      database: {
        poolSize: cfg.database.poolSize,
        connectionTimeout: cfg.database.connectionTimeout,
      },
      jwt: {
        issuer: cfg.jwt.issuer,
        audience: cfg.jwt.audience,
        accessTokenExpiry: cfg.jwt.accessTokenExpiry,
      },
      email: {
        verificationEnabled: cfg.email.verificationEnabled,
        passwordResetEnabled: cfg.email.passwordResetEnabled,
      },
      oauth: {
        google: {
          enabled: cfg.oauth.google.enabled,
        },
      },
      rateLimiting: cfg.rateLimiting,
      cors: cfg.cors,
    };

    logger.info('Application configuration', safeConfig);
  }
}
```

## Best Practices

### 1. Environment Variable Naming
- Use consistent prefixing (e.g., `DATABASE_`, `JWT_`, `EMAIL_`)
- Use SCREAMING_SNAKE_CASE for environment variables
- Include units in variable names when applicable (e.g., `TIMEOUT_MS`)

### 2. Secret Management
- Never commit secrets to version control
- Use different secrets for different environments
- Rotate secrets regularly
- Use secure secret management tools (Doppler, AWS Secrets Manager, etc.)

### 3. Configuration Validation
- Validate configuration at startup
- Provide meaningful error messages
- Use schema validation (Zod, Joi, etc.)
- Log configuration (without secrets) for debugging

### 4. Environment Separation
- Maintain separate configurations for each environment
- Use feature flags for environment-specific behavior
- Document all configuration options
- Provide sensible defaults

### 5. Security Considerations
- Use strong, random secrets in production
- Enable security features by default
- Validate all user-provided configuration
- Monitor configuration changes

This comprehensive configuration system ensures that the Tamatar Auth service can be properly configured for different environments while maintaining security and reliability.
