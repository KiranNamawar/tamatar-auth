# Environment Variables and Configuration

This guide covers environment variable management, configuration patterns, and best practices for the Tamatar Auth microservice.

## Required Environment Variables

### Production Environment Setup

```bash
# =============================================================================
# CORE CONFIGURATION
# =============================================================================
NODE_ENV="production"
PORT=3000
HOST="0.0.0.0"

# =============================================================================
# DATABASE CONFIGURATION
# =============================================================================
DATABASE_URL="postgresql://username:password@host:port/database"
DATABASE_POOL_SIZE=10
DATABASE_CONNECTION_TIMEOUT=5000
DATABASE_QUERY_TIMEOUT=10000

# =============================================================================
# JWT & AUTHENTICATION
# =============================================================================
JWT_SECRET="your-super-secure-256-bit-secret-key-here"
JWT_ACCESS_TOKEN_EXPIRY="15m"
JWT_REFRESH_TOKEN_EXPIRY="7d"
JWT_ISSUER="tamatar-auth"
JWT_AUDIENCE="tamatar-services"

# =============================================================================
# EMAIL SERVICE
# =============================================================================
RESEND_API_KEY="re_your_resend_api_key"
FROM_EMAIL="Tamatar Auth <auth@email.tamatar.dev>"
REPLY_TO_EMAIL="support@tamatar.dev"

# Email Features
EMAIL_VERIFICATION_ENABLED=true
PASSWORD_RESET_ENABLED=true
LOGIN_NOTIFICATIONS_ENABLED=false

# =============================================================================
# OAUTH CONFIGURATION
# =============================================================================
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"
GOOGLE_REDIRECT_URI="https://auth.tamatar.dev/oauth/google/callback"

# =============================================================================
# SECURITY CONFIGURATION
# =============================================================================
# CORS
CORS_ORIGIN="https://app.tamatar.dev,https://admin.tamatar.dev"
CORS_CREDENTIALS=true

# Rate Limiting
RATE_LIMIT_ENABLED=true
RATE_LIMIT_WINDOW="15m"
RATE_LIMIT_MAX_REQUESTS=100

# Authentication Rate Limits
LOGIN_RATE_LIMIT_MAX=5
LOGIN_RATE_LIMIT_WINDOW="15m"
REGISTER_RATE_LIMIT_MAX=3
REGISTER_RATE_LIMIT_WINDOW="1h"

# =============================================================================
# FRONTEND URLS
# =============================================================================
FRONTEND_URL="https://app.tamatar.dev"
ADMIN_URL="https://admin.tamatar.dev"
AUTH_URL="https://auth.tamatar.dev"

# =============================================================================
# MONITORING & LOGGING
# =============================================================================
LOG_LEVEL="info"
LOG_FORMAT="json"
SENTRY_DSN="https://your-sentry-dsn"
SENTRY_ENVIRONMENT="production"

# =============================================================================
# CACHE CONFIGURATION
# =============================================================================
REDIS_URL="redis://localhost:6379"
CACHE_TTL="1h"
CACHE_PREFIX="tamatar:auth:"
```

## Environment-Specific Configurations

### Development (.env.development)

```bash
NODE_ENV="development"
PORT=3000
LOG_LEVEL="debug"

# Local Database
DATABASE_URL="postgresql://dev_user:dev_pass@localhost:5432/tamatar_auth_dev"

# Development JWT Secret (not for production)
JWT_SECRET="dev-secret-key-change-in-production"

# Development Features
EMAIL_VERIFICATION_ENABLED=false  # Skip email verification in dev
RATE_LIMIT_ENABLED=false          # Disable rate limiting in dev
CORS_ORIGIN="http://localhost:3000,http://localhost:3001"

# Development URLs
FRONTEND_URL="http://localhost:3000"
AUTH_URL="http://localhost:3000"

# Test Email Service
RESEND_API_KEY="re_test_key_here"
FROM_EMAIL="test@example.com"
```

### Testing (.env.test)

```bash
NODE_ENV="test"
PORT=3001
LOG_LEVEL="error"                 # Reduce noise in tests

# Test Database
DATABASE_URL="postgresql://test_user:test_pass@localhost:5432/tamatar_auth_test"

# Test Configuration
JWT_SECRET="test-secret-key"
EMAIL_VERIFICATION_ENABLED=false
RATE_LIMIT_ENABLED=false

# Disable external services in tests
RESEND_API_KEY="test-key"
SENTRY_DSN=""
```

## Configuration Service Pattern

### Type-Safe Configuration

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
    secret: z.string().min(32, 'JWT secret must be at least 32 characters'),
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
    rateLimits: z.object({
      perHour: z.coerce.number().default(5),
      perDay: z.coerce.number().default(20),
    }),
  }),

  // Security
  security: z.object({
    corsOrigin: z.union([z.string(), z.array(z.string())]).default('*'),
    corsCredentials: z.boolean().default(true),
    rateLimitEnabled: z.boolean().default(true),
    rateLimitWindow: z.string().default('15m'),
    rateLimitMax: z.coerce.number().default(100),
  }),

  // URLs
  urls: z.object({
    frontend: z.string().url(),
    admin: z.string().url().optional(),
    auth: z.string().url(),
  }),

  // Monitoring
  monitoring: z.object({
    logLevel: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
    logFormat: z.enum(['json', 'simple']).default('json'),
    sentryDsn: z.string().optional(),
    sentryEnvironment: z.string().optional(),
  }),

  // Features
  features: z.object({
    registrationEnabled: z.boolean().default(true),
    oauthEnabled: z.boolean().default(true),
    passwordResetEnabled: z.boolean().default(true),
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
        rateLimits: {
          perHour: process.env.EMAIL_RATE_LIMIT_PER_HOUR,
          perDay: process.env.EMAIL_RATE_LIMIT_PER_DAY,
        },
      },

      security: {
        corsOrigin: process.env.CORS_ORIGIN?.split(',') || '*',
        corsCredentials: process.env.CORS_CREDENTIALS !== 'false',
        rateLimitEnabled: process.env.RATE_LIMIT_ENABLED !== 'false',
        rateLimitWindow: process.env.RATE_LIMIT_WINDOW,
        rateLimitMax: process.env.RATE_LIMIT_MAX_REQUESTS,
      },

      urls: {
        frontend: process.env.FRONTEND_URL,
        admin: process.env.ADMIN_URL,
        auth: process.env.AUTH_URL,
      },

      monitoring: {
        logLevel: process.env.LOG_LEVEL,
        logFormat: process.env.LOG_FORMAT,
        sentryDsn: process.env.SENTRY_DSN,
        sentryEnvironment: process.env.SENTRY_ENVIRONMENT,
      },

      features: {
        registrationEnabled: process.env.FEATURE_REGISTRATION_ENABLED !== 'false',
        oauthEnabled: process.env.FEATURE_OAUTH_ENABLED !== 'false',
        passwordResetEnabled: process.env.FEATURE_PASSWORD_RESET_ENABLED !== 'false',
      },
    };

    try {
      return configSchema.parse(rawConfig);
    } catch (error) {
      console.error('❌ Configuration validation failed:', error);
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

### Configuration Validation

```typescript
// src/lib/config/validator.ts
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

    // Validate production settings
    if (cfg.nodeEnv === 'production') {
      if (cfg.jwt.secret === 'development-secret') {
        errors.push('Development JWT secret cannot be used in production');
      }
      
      if (!cfg.monitoring.sentryDsn) {
        logger.warn('⚠️ Sentry DSN not configured for production');
      }
      
      if (!cfg.security.rateLimitEnabled) {
        errors.push('Rate limiting must be enabled in production');
      }
    }

    if (errors.length > 0) {
      logger.error('❌ Configuration validation failed', { errors });
      throw new Error(`Configuration errors: ${errors.join(', ')}`);
    }

    logger.info('✅ Configuration validated successfully');
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
      security: {
        rateLimitEnabled: cfg.security.rateLimitEnabled,
        corsCredentials: cfg.security.corsCredentials,
      },
    };

    logger.info('📋 Application configuration', safeConfig);
  }
}
```

## Elysia Configuration Plugin

```typescript
// src/lib/config/plugin.ts
export const configPlugin = new Elysia({ name: 'config' })
  .decorate({
    config: config.get()
  })
  .onStart(() => {
    ConfigValidator.validate();
    ConfigValidator.logConfiguration();
  })
  .as('global');

// Usage in other plugins
export const jwtPlugin = new Elysia({ name: 'jwt' })
  .use(configPlugin)
  .use(jwt(({ config }) => ({
    secret: config.jwt.secret,
    exp: config.jwt.accessTokenExpiry,
    iss: config.jwt.issuer,
    aud: config.jwt.audience
  })))
  .as('scoped');

export const corsPlugin = new Elysia({ name: 'cors' })
  .use(configPlugin)
  .use(cors(({ config }) => ({
    origin: config.security.corsOrigin,
    credentials: config.security.corsCredentials,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS']
  })))
  .as('global');
```

## Secret Management

### Using External Secret Managers

#### AWS Secrets Manager

```typescript
// src/lib/config/secrets/aws.ts
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

export class AWSSecretsManager {
  private client: SecretsManagerClient;

  constructor(region: string = 'us-east-1') {
    this.client = new SecretsManagerClient({ region });
  }

  async getSecret(secretName: string): Promise<string> {
    try {
      const command = new GetSecretValueCommand({ SecretId: secretName });
      const response = await this.client.send(command);
      return response.SecretString || "";
    } catch (error) {
      logger.error(`Failed to retrieve secret ${secretName}:`, error);
      throw new Error(`Secret retrieval failed: ${secretName}`);
    }
  }

  async getSecrets(secretNames: string[]): Promise<Record<string, string>> {
    const secrets = await Promise.all(
      secretNames.map(async (name) => ({
        [name]: await this.getSecret(name)
      }))
    );
    
    return Object.assign({}, ...secrets);
  }
}

// Usage in configuration
export async function loadSecretsFromAWS(): Promise<void> {
  if (process.env.NODE_ENV === 'production' && process.env.USE_AWS_SECRETS === 'true') {
    const secretsManager = new AWSSecretsManager();
    
    const secrets = await secretsManager.getSecrets([
      'tamatar-auth/jwt-secret',
      'tamatar-auth/database-url',
      'tamatar-auth/resend-api-key'
    ]);
    
    // Override environment variables with secrets
    process.env.JWT_SECRET = secrets['tamatar-auth/jwt-secret'];
    process.env.DATABASE_URL = secrets['tamatar-auth/database-url'];
    process.env.RESEND_API_KEY = secrets['tamatar-auth/resend-api-key'];
  }
}
```

#### Doppler Integration

```typescript
// src/lib/config/secrets/doppler.ts
export class DopplerConfig {
  static async loadSecrets(): Promise<void> {
    if (process.env.DOPPLER_TOKEN) {
      try {
        const response = await fetch('https://api.doppler.com/v3/configs/config/secrets/download', {
          headers: {
            'Authorization': `Bearer ${process.env.DOPPLER_TOKEN}`,
            'Accept': 'application/json'
          }
        });
        
        if (!response.ok) {
          throw new Error(`Doppler API error: ${response.status}`);
        }
        
        const secrets = await response.json();
        
        // Apply secrets to environment
        Object.entries(secrets).forEach(([key, value]) => {
          process.env[key] = value as string;
        });
        
        logger.info('✅ Secrets loaded from Doppler');
      } catch (error) {
        logger.error('❌ Failed to load secrets from Doppler:', error);
        throw error;
      }
    }
  }
}
```

## Feature Flags

### Configuration-Based Feature Flags

```typescript
// src/lib/config/features.ts
export class FeatureFlags {
  constructor(private config: Config) {}

  isRegistrationEnabled(): boolean {
    return this.config.features.registrationEnabled;
  }

  isOAuthEnabled(): boolean {
    return this.config.features.oauthEnabled;
  }

  isPasswordResetEnabled(): boolean {
    return this.config.features.passwordResetEnabled;
  }

  isEmailVerificationRequired(): boolean {
    return this.config.email.verificationEnabled;
  }

  // Environment-specific features
  isDevelopmentFeatureEnabled(feature: string): boolean {
    return this.config.nodeEnv === 'development' && 
           process.env[`DEV_FEATURE_${feature.toUpperCase()}`] === 'true';
  }
}

// Elysia plugin for feature flags
export const featureFlagsPlugin = new Elysia({ name: 'feature-flags' })
  .use(configPlugin)
  .derive(({ config }) => ({
    features: new FeatureFlags(config)
  }))
  .as('scoped');

// Usage in routes
export const authRoutes = new Elysia({ prefix: '/auth' })
  .use(featureFlagsPlugin)
  .post('/register', ({ features, body, error }) => {
    if (!features.isRegistrationEnabled()) {
      return error(503, 'Registration is currently disabled');
    }
    
    return registerUser(body);
  })
  .post('/oauth/google', ({ features, error }) => {
    if (!features.isOAuthEnabled()) {
      return error(503, 'OAuth is currently disabled');
    }
    
    return initiateGoogleOAuth();
  });
```

## Environment Variable Best Practices

### Naming Conventions

```bash
# ✅ Good - Descriptive and grouped
DATABASE_URL="..."
DATABASE_POOL_SIZE=10
DATABASE_CONNECTION_TIMEOUT=5000

JWT_SECRET="..."
JWT_ACCESS_TOKEN_EXPIRY="15m"
JWT_REFRESH_TOKEN_EXPIRY="7d"

EMAIL_SERVICE_API_KEY="..."
EMAIL_FROM_ADDRESS="..."
EMAIL_RATE_LIMIT_PER_HOUR=5

# ❌ Bad - Inconsistent and unclear
DB_URL="..."
SECRET="..."
API_KEY="..."
TIMEOUT=5000
```

### Validation Patterns

```typescript
// ✅ Good - Validate early and fail fast
export function validateRequiredEnvVars(): void {
  const required = [
    'DATABASE_URL',
    'JWT_SECRET',
    'RESEND_API_KEY'
  ];

  const missing = required.filter(key => !process.env[key]);
  
  if (missing.length > 0) {
    console.error(`❌ Missing required environment variables: ${missing.join(', ')}`);
    process.exit(1);
  }
}

// ✅ Good - Type conversion with validation
export function getPortFromEnv(): number {
  const port = process.env.PORT;
  const parsed = port ? parseInt(port, 10) : 3000;
  
  if (isNaN(parsed) || parsed < 1 || parsed > 65535) {
    throw new Error(`Invalid PORT value: ${port}`);
  }
  
  return parsed;
}

// ✅ Good - Boolean conversion
export function getBooleanFromEnv(key: string, defaultValue: boolean = false): boolean {
  const value = process.env[key];
  if (value === undefined) return defaultValue;
  return value.toLowerCase() === 'true';
}
```

### Security Best Practices

```typescript
// ✅ Good - Mask secrets in logs
export function logSafeEnvironmentInfo(): void {
  const safeEnvVars = {
    NODE_ENV: process.env.NODE_ENV,
    PORT: process.env.PORT,
    LOG_LEVEL: process.env.LOG_LEVEL,
    DATABASE_HOST: process.env.DATABASE_URL?.split('@')[1]?.split('/')[0], // Only host
    // Never log full DATABASE_URL, JWT_SECRET, API keys, etc.
  };
  
  logger.info('Environment configuration', safeEnvVars);
}

// ✅ Good - Validate secret strength
export function validateJWTSecret(secret: string): void {
  if (secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters for security');
  }
  
  if (secret === 'development-secret' && process.env.NODE_ENV === 'production') {
    throw new Error('Development JWT secret cannot be used in production');
  }
}
```

This configuration guide ensures secure, maintainable, and environment-appropriate configuration management for the Tamatar Auth microservice.
