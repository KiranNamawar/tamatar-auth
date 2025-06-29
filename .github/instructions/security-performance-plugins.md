# Security & Performance Plugins

This file covers Elysia.js security and performance plugins configuration and usage patterns for the Tamatar Auth microservice.

## CORS Plugin (@elysiajs/cors)

Reference: [Elysia.js CORS Plugin](https://elysiajs.com/plugins/cors.html)

### Basic CORS Setup

```typescript
import { cors } from '@elysiajs/cors';

// Basic CORS setup
export const corsPlugin = new Elysia({ name: 'cors' })
  .use(cors({
    origin: process.env.NODE_ENV === 'production' 
      ? ['https://app.tamatar.dev', 'https://admin.tamatar.dev']
      : true, // Allow all origins in development
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposeHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
    maxAge: 86400, // 24 hours
    preflight: true
  }))
  .as('global');

// Dynamic CORS with function
export const dynamicCorsPlugin = new Elysia({ name: 'dynamic-cors' })
  .use(cors({
    origin: (context) => {
      const origin = context.request.headers.get('origin');
      const allowedOrigins = ['https://app.tamatar.dev', 'https://admin.tamatar.dev'];
      
      // Allow specific origins or localhost in development
      if (process.env.NODE_ENV === 'development' && origin?.includes('localhost')) {
        return true;
      }
      
      return allowedOrigins.includes(origin || '');
    },
    credentials: true
  }))
  .as('global');

// CORS for API with subdomain pattern
export const apiCorsPlugin = new Elysia({ name: 'api-cors' })
  .use(cors({
    origin: /.*\.tamatar\.dev$/, // Allow all tamatar.dev subdomains
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-API-Key'],
    maxAge: 3600
  }))
  .as('global');

// Usage in application
export const app = new Elysia({ name: 'tamatar-auth' })
  .use(corsPlugin)
  .get('/health', () => ({ status: 'ok' }));
```

## JWT Plugin (@elysiajs/jwt)

Reference: [Elysia.js JWT Plugin](https://elysiajs.com/plugins/jwt.html)

### JWT Service Plugin with Multiple Configurations

```typescript
import { jwt } from '@elysiajs/jwt';

// JWT service plugin with multiple configurations
export const jwtPlugin = new Elysia({ name: 'jwt' })
  .use(jwt({
    name: 'jwt',
    secret: process.env.JWT_SECRET!,
    exp: '15m', // Access token expiration
    iss: 'tamatar-auth',
    aud: 'tamatar-services'
  }))
  .use(jwt({
    name: 'refreshJWT',
    secret: process.env.JWT_REFRESH_SECRET!,
    exp: '7d', // Refresh token expiration
    iss: 'tamatar-auth',
    aud: 'tamatar-services'
  }))
  .derive(({ jwt, refreshJWT }) => ({
    // Enhanced JWT utilities
    auth: {
      async signTokens(payload: UserPayload) {
        const accessToken = await jwt.sign(payload);
        const refreshToken = await refreshJWT.sign({ 
          sub: payload.sub, 
          type: 'refresh' 
        });
        
        return {
          accessToken,
          refreshToken,
          expiresIn: 15 * 60 // 15 minutes in seconds
        };
      },
      
      async verifyAccess(token: string) {
        try {
          return await jwt.verify(token);
        } catch (error) {
          throw new Error('Invalid or expired access token');
        }
      },
      
      async verifyRefresh(token: string) {
        try {
          const payload = await refreshJWT.verify(token);
          if (payload.type !== 'refresh') {
            throw new Error('Invalid refresh token type');
          }
          return payload;
        } catch (error) {
          throw new Error('Invalid or expired refresh token');
        }
      }
    }
  }))
  .as('scoped');

// Authentication middleware using JWT
export const authMiddleware = new Elysia({ name: 'auth-middleware' })
  .use(jwtPlugin)
  .derive(({ headers, auth }) => ({
    user: null as UserPayload | null
  }))
  .resolve(async ({ headers, auth }) => {
    const authorization = headers.authorization;
    if (!authorization?.startsWith('Bearer ')) {
      return {};
    }
    
    const token = authorization.replace('Bearer ', '');
    try {
      const payload = await auth.verifyAccess(token);
      return { user: payload };
    } catch (error) {
      return {};
    }
  })
  .macro(({ onBeforeHandle }) => ({
    requireAuth(enabled: boolean) {
      if (!enabled) return;
      return onBeforeHandle(({ user, error }) => {
        if (!user) {
          return error(401, {
            error: 'Authentication required',
            code: 'MISSING_AUTH'
          });
        }
      });
    },
    requireRole(role: string) {
      return onBeforeHandle(({ user, error }) => {
        if (!user?.roles?.includes(role)) {
          return error(403, {
            error: `Role required: ${role}`,
            code: 'INSUFFICIENT_ROLE'
          });
        }
      });
    }
  }))
  .as('scoped');

// Usage in routes
export const protectedRoutes = new Elysia({ prefix: '/api' })
  .use(authMiddleware)
  .get('/profile', ({ user }) => ({ user }), {
    requireAuth: true
  })
  .delete('/admin/users/:id', ({ params, user }) => {
    return deleteUser(params.id, user);
  }, {
    requireAuth: true,
    requireRole: 'admin'
  });
```

## Bearer Plugin (@elysiajs/bearer)

Reference: [Elysia.js Bearer Plugin](https://elysiajs.com/plugins/bearer.html)

### Bearer Token Extraction Plugin

```typescript
import { bearer } from '@elysiajs/bearer';

// Bearer token extraction plugin
export const bearerPlugin = new Elysia({ name: 'bearer' })
  .use(bearer())
  .derive(({ bearer }) => ({
    // Enhanced bearer token utilities
    bearerAuth: {
      validateToken: async (token: string) => {
        if (!token) throw new Error('Bearer token required');
        
        // Custom validation logic here
        const payload = await validateAPIKey(token);
        return payload;
      },
      
      extractToken: () => bearer,
      
      requireToken: (token: string | undefined) => {
        if (!token) {
          throw new Error('Bearer authorization required');
        }
        return token;
      }
    }
  }))
  .as('scoped');

// API Key authentication using Bearer
export const apiKeyAuth = new Elysia({ name: 'api-key-auth' })
  .use(bearerPlugin)
  .macro(({ onBeforeHandle }) => ({
    requireAPIKey(enabled: boolean) {
      if (!enabled) return;
      return onBeforeHandle(async ({ bearerAuth, error, set }) => {
        try {
          const token = bearerAuth.extractToken();
          if (!token) {
            set.headers['WWW-Authenticate'] = 'Bearer realm="api", error="invalid_request"';
            return error(401, {
              error: 'Bearer token required',
              code: 'MISSING_BEARER_TOKEN'
            });
          }
          
          await bearerAuth.validateToken(token);
        } catch (err) {
          set.headers['WWW-Authenticate'] = 'Bearer realm="api", error="invalid_token"';
          return error(401, {
            error: 'Invalid bearer token',
            code: 'INVALID_BEARER_TOKEN'
          });
        }
      });
    }
  }))
  .as('scoped');

// Public API with Bearer authentication
export const apiRoutes = new Elysia({ prefix: '/api/v1' })
  .use(apiKeyAuth)
  .get('/public', () => ({ message: 'Public endpoint' }))
  .get('/private', ({ bearerAuth }) => {
    return { 
      message: 'Authenticated endpoint',
      token: bearerAuth.extractToken()
    };
  }, {
    requireAPIKey: true
  });
```

## Rate Limiting Plugin (elysia-rate-limit)

Reference: [Elysia.js Rate Limit Plugin](https://elysiajs.com/plugins/rate-limit.html)

### Basic Rate Limiting

```typescript
import { rateLimit } from 'elysia-rate-limit';

// Basic rate limiting
export const rateLimitPlugin = new Elysia({ name: 'rate-limit' })
  .use(rateLimit({
    duration: 60000, // 1 minute window
    max: 100, // 100 requests per minute
    errorResponse: 'Rate limit exceeded. Please try again later.',
    headers: true,
    scoping: 'global'
  }))
  .as('global');

// Authentication-specific rate limiting
export const authRateLimit = new Elysia({ name: 'auth-rate-limit' })
  .use(rateLimit({
    duration: 15 * 60 * 1000, // 15 minutes
    max: 5, // 5 login attempts per 15 minutes
    generator: (req) => {
      // Rate limit by email from request body for login attempts
      const body = req.body ? JSON.parse(req.body) : {};
      return body.email || req.headers.get('x-forwarded-for') || 'unknown';
    },
    errorResponse: new Response(
      JSON.stringify({
        error: 'Too many login attempts',
        code: 'RATE_LIMIT_EXCEEDED',
        retryAfter: 900 // 15 minutes
      }),
      { 
        status: 429,
        headers: { 'Content-Type': 'application/json' }
      }
    ),
    skip: (req) => {
      // Skip rate limiting for health checks
      return req.url.endsWith('/health');
    }
  }))
  .as('scoped');

// IP-based rate limiting with custom context
export const ipRateLimit = new Elysia({ name: 'ip-rate-limit' })
  .use(rateLimit({
    duration: 60000, // 1 minute
    max: 60, // 60 requests per minute per IP
    generator: (req, server) => {
      // Handle requests behind reverse proxy
      const forwardedFor = req.headers.get('x-forwarded-for');
      const realIP = req.headers.get('x-real-ip');
      const clientIP = server?.requestIP(req)?.address;
      
      // Use forwarded IP if behind proxy, otherwise use direct IP
      return forwardedFor?.split(',')[0]?.trim() || realIP || clientIP || 'unknown';
    },
    countFailedRequest: false, // Don't count failed requests
    context: new DefaultContext(10000), // Larger cache for IPs
    errorResponse: (req) => {
      return new Response(
        JSON.stringify({
          error: 'Rate limit exceeded',
          code: 'TOO_MANY_REQUESTS',
          ip: req.headers.get('x-forwarded-for') || 'hidden'
        }),
        { status: 429, headers: { 'Content-Type': 'application/json' } }
      );
    }
  }))
  .as('global');

// Endpoint-specific rate limiting
export const endpointRateLimit = new Elysia({ name: 'endpoint-rate-limit' })
  .use(rateLimit({
    duration: 3600000, // 1 hour
    max: 10, // 10 password resets per hour
    generator: (req) => {
      // Combine IP and endpoint for granular limiting
      const ip = req.headers.get('x-forwarded-for') || 'unknown';
      const endpoint = new URL(req.url).pathname;
      return `${ip}:${endpoint}`;
    },
    errorResponse: new Error('Password reset limit exceeded'),
    scoping: 'scoped'
  }))
  .as('scoped');

// Usage in authentication routes
export const authRoutes = new Elysia({ prefix: '/auth' })
  .use(corsPlugin)
  .use(jwtPlugin)
  .use(authRateLimit)
  .post('/login', async ({ body, auth }) => {
    const tokens = await auth.signTokens(body);
    return { tokens };
  })
  .use(endpointRateLimit)
  .post('/forgot-password', ({ body }) => {
    return sendPasswordReset(body.email);
  });
```

## Complete Security Stack

### Integrated Security Configuration

```typescript
// Complete security stack
export const securityStack = new Elysia({ name: 'security-stack' })
  .use(corsPlugin)
  .use(rateLimitPlugin)
  .use(jwtPlugin)
  .use(bearerPlugin)
  .use(authMiddleware)
  .as('global');

// Main application with all security plugins
export const app = new Elysia({ name: 'tamatar-auth' })
  .use(securityStack)
  .get('/health', () => ({ status: 'ok' }))
  .group('/auth', (app) => 
    app
      .use(authRateLimit)
      .post('/login', loginHandler)
      .post('/register', registerHandler)
  )
  .group('/api', (app) =>
    app
      .use(apiKeyAuth)
      .get('/profile', profileHandler, { requireAuth: true })
      .delete('/admin/*', adminHandler, { requireAPIKey: true })
  );
```

## Security Headers Plugin

### Custom Security Headers Implementation

```typescript
export const securityHeadersPlugin = new Elysia({ name: 'security-headers' })
  .onResponse(({ set, request }) => {
    // Set security headers
    set.headers = {
      ...set.headers,
      // Content Security Policy
      'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';",
      
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
      'Server': 'Tamatar-Auth'
    };

    // Add cache control for sensitive endpoints
    if (request.url.includes('/auth/') || request.url.includes('/api/')) {
      set.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate';
      set.headers['Pragma'] = 'no-cache';
      set.headers['Expires'] = '0';
    }
  })
  .as('global');
```

## Plugin Configuration Best Practices

### Environment-Specific Configuration

```typescript
// Development configuration
const developmentSecurity = new Elysia({ name: 'dev-security' })
  .use(cors({ origin: true })) // Allow all origins
  .use(rateLimit({ max: 1000, duration: 60000 })) // Generous limits
  .as('global');

// Production configuration
const productionSecurity = new Elysia({ name: 'prod-security' })
  .use(cors({
    origin: ['https://app.tamatar.dev', 'https://admin.tamatar.dev'],
    credentials: true
  }))
  .use(rateLimit({ max: 100, duration: 60000 })) // Stricter limits
  .use(securityHeadersPlugin)
  .as('global');

// Use appropriate configuration based on environment
export const securityConfig = process.env.NODE_ENV === 'production' 
  ? productionSecurity 
  : developmentSecurity;
```

### Performance Monitoring

```typescript
export const performancePlugin = new Elysia({ name: 'performance' })
  .derive(() => ({
    startTime: Date.now()
  }))
  .onResponse(({ request, startTime, set }) => {
    const duration = Date.now() - startTime;
    
    // Add performance headers
    set.headers['X-Response-Time'] = `${duration}ms`;
    
    // Log slow requests
    if (duration > 1000) {
      logger.warn('Slow request detected', {
        method: request.method,
        url: request.url,
        duration
      });
    }
  })
  .as('global');
```

## Testing Security Plugins

### Security Plugin Testing Patterns

```typescript
// Test security configurations
describe('Security Plugins', () => {
  it('should set CORS headers correctly', async () => {
    const app = new Elysia().use(corsPlugin).get('/', () => 'ok');
    
    const response = await app.handle(
      new Request('http://localhost/', {
        headers: { Origin: 'https://app.tamatar.dev' }
      })
    );
    
    expect(response.headers.get('Access-Control-Allow-Origin')).toBe('https://app.tamatar.dev');
  });
  
  it('should enforce rate limits', async () => {
    const app = new Elysia()
      .use(rateLimit({ max: 2, duration: 60000 }))
      .get('/', () => 'ok');
    
    // First two requests should succeed
    await app.handle(new Request('http://localhost/'));
    await app.handle(new Request('http://localhost/'));
    
    // Third request should be rate limited
    const response = await app.handle(new Request('http://localhost/'));
    expect(response.status).toBe(429);
  });
});
```

These security and performance plugins provide comprehensive protection and monitoring for the Tamatar Auth microservice while maintaining high performance and developer experience.
