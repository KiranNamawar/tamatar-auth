# Elysia.js Advanced Patterns

This file covers advanced Elysia.js patterns for the Tamatar Auth microservice, including guards, macros, dependency injection, and complex lifecycle management.

## Guard Patterns

Guards provide scoped middleware application for route groups with clean separation. Reference: [Elysia.js Guard Patterns](https://elysiajs.com/patterns/guard.html)

### Authentication Guard with Scoped Application

```typescript
// Authentication guard with scoped application
export const authGuard = new Elysia({ name: 'auth-guard' })
  .derive(({ headers }) => ({
    authToken: headers.authorization?.replace('Bearer ', ''),
    userId: null as string | null
  }))
  .resolve(async ({ authToken }) => {
    if (!authToken) return {};
    
    try {
      const payload = jwt.verify(authToken);
      return { userId: payload.sub, user: await getUser(payload.sub) };
    } catch {
      return {};
    }
  })
  .macro(({ onBeforeHandle }) => ({
    auth(enabled: boolean) {
      if (!enabled) return;
      return onBeforeHandle(({ userId, error }) => {
        if (!userId) return error(401, 'Authentication required');
      });
    },
    requireRole(role: string) {
      return onBeforeHandle(({ user, error }) => {
        if (!user?.roles?.includes(role)) {
          return error(403, `Role ${role} required`);
        }
      });
    }
  }));

// Apply guard to route groups
export const protectedRoutes = new Elysia({ prefix: '/api' })
  .use(authGuard)
  .group('/admin', {
    beforeHandle: ({ user, error }) => {
      if (!user?.roles?.includes('admin')) {
        return error(403, 'Admin access required');
      }
    }
  }, (app) => 
    app
      .get('/users', ({ user }) => getUsersAsAdmin(user), {
        auth: true,
        requireRole: 'admin'
      })
      .delete('/users/:id', ({ params, user }) => deleteUser(params.id, user), {
        auth: true,
        requireRole: 'admin'
      })
  )
  .group('/user', (app) =>
    app.guard({
      beforeHandle: ({ userId, error }) => {
        if (!userId) return error(401, 'Authentication required');
      }
    }, (protectedApp) =>
      protectedApp
        .get('/profile', ({ user }) => user)
        .patch('/profile', ({ body, userId }) => updateProfile(userId, body), {
          body: t.Object({
            name: t.Optional(t.String()),
            email: t.Optional(t.String({ format: 'email' }))
          })
        })
    )
  );
```

## Macro v2 Patterns

Macros enable reusable complex logic with full type safety. Reference: [Elysia.js Macro System](https://elysiajs.com/patterns/macro.html)

### Advanced Authentication Macro with Role-Based Access

```typescript
// Advanced authentication macro with role-based access
export const authMacro = new Elysia({ name: 'auth-macro' })
  .macro({
    // Property shorthand - boolean parameter
    isAuthenticated: {
      resolve: async ({ headers }) => {
        const token = headers.authorization?.replace('Bearer ', '');
        if (!token) return {};
        
        try {
          const payload = jwt.verify(token);
          const user = await getUserById(payload.sub);
          return { userId: payload.sub, user };
        } catch {
          return {};
        }
      },
      beforeHandle: ({ userId, error }) => {
        if (!userId) return error(401, 'Authentication required');
      }
    },
    
    // Function macro with parameters
    requirePermission(permission: string) {
      return {
        resolve: async ({ userId }) => {
          if (!userId) return {};
          const permissions = await getUserPermissions(userId);
          return { permissions };
        },
        beforeHandle: ({ permissions, error }) => {
          if (!permissions?.includes(permission)) {
            return error(403, `Permission required: ${permission}`);
          }
        }
      };
    },
    
    // Rate limiting macro
    rateLimit(options: { max: number; window: number; identifier?: string }) {
      return {
        beforeHandle: async ({ headers, error, query }) => {
          const identifier = options.identifier || 
            headers['x-forwarded-for'] || 
            headers['x-real-ip'] || 
            'unknown';
          
          const allowed = await checkRateLimit(identifier, options);
          if (!allowed) {
            return error(429, 'Rate limit exceeded');
          }
        }
      };
    },
    
    // Audit logging macro
    audit(action: string) {
      return {
        onResponse: ({ userId, request, response }) => {
          logAuditEvent({
            userId,
            action,
            method: request.method,
            path: request.url,
            status: response.status,
            timestamp: new Date()
          });
        }
      };
    }
  })
  .as('global');

// Usage with multiple macros
export const adminRoutes = new Elysia({ prefix: '/admin' })
  .use(authMacro)
  .delete('/users/:id', ({ params, userId }) => {
    return deleteUser(params.id, userId);
  }, {
    isAuthenticated: true,
    requirePermission: 'user:delete',
    rateLimit: { max: 10, window: 60000 },
    audit: 'user_deletion'
  })
  .patch('/settings', ({ body }) => updateSettings(body), {
    isAuthenticated: true,
    requirePermission: 'settings:write',
    audit: 'settings_update',
    body: t.Object({
      key: t.String(),
      value: t.Any()
    })
  });
```

## Dependency Injection Patterns

Advanced state and service management. Reference: [Elysia.js Dependency Injection](https://elysiajs.com/patterns/dependency-injection.html)

### Service Layer with Dependency Injection

```typescript
// Service layer with dependency injection
export const databaseService = new Elysia({ name: 'database' })
  .decorate({
    db: new PrismaClient(),
    cache: new Redis(process.env.REDIS_URL)
  })
  .onStop(({ db, cache }) => {
    // Cleanup on shutdown
    return Promise.all([
      db.$disconnect(),
      cache.quit()
    ]);
  });

export const emailService = new Elysia({ name: 'email' })
  .decorate({
    resend: new Resend(process.env.RESEND_API_KEY),
    emailQueue: new Queue('email')
  })
  .derive(({ resend }) => ({
    sendEmail: async (to: string, subject: string, html: string) => {
      return await resend.emails.send({
        from: 'auth@tamatar.dev',
        to,
        subject,
        html
      });
    }
  }));

export const authService = new Elysia({ name: 'auth' })
  .use(databaseService)
  .use(emailService)
  .derive(({ db, cache, sendEmail }) => ({
    // Injected auth service with dependencies
    authService: {
      async createUser(userData: UserCreateData) {
        return await db.$transaction(async (tx) => {
          const user = await tx.user.create({ data: userData });
          
          // Send welcome email using injected service
          await sendEmail(
            user.email,
            'Welcome to Tamatar',
            welcomeEmailTemplate(user)
          );
          
          // Cache user data
          await cache.setex(`user:${user.id}`, 3600, JSON.stringify(user));
          
          return user;
        });
      },
      
      async authenticateUser(email: string, password: string) {
        // Check cache first
        const cached = await cache.get(`auth:${email}`);
        if (cached) return JSON.parse(cached);
        
        const user = await db.user.findUnique({ where: { email } });
        if (!user || !await bcrypt.compare(password, user.password)) {
          throw new Error('Invalid credentials');
        }
        
        // Cache successful auth
        await cache.setex(`auth:${email}`, 300, JSON.stringify(user));
        return user;
      }
    }
  }))
  .as('scoped');

// Route usage with injected services
export const authRoutes = new Elysia({ prefix: '/auth' })
  .use(authService)
  .post('/register', async ({ body, authService }) => {
    const user = await authService.createUser(body);
    return { user: sanitizeUser(user) };
  }, {
    body: t.Object({
      email: t.String({ format: 'email' }),
      password: t.String({ minLength: 8 }),
      firstName: t.String()
    })
  })
  .post('/login', async ({ body, authService }) => {
    const user = await authService.authenticateUser(body.email, body.password);
    const token = generateJWT(user);
    return { user: sanitizeUser(user), token };
  }, {
    body: t.Object({
      email: t.String({ format: 'email' }),
      password: t.String()
    })
  });
```

## Reference Model Patterns

Consistent schema management across the application. Reference: [Elysia.js Reference Models](https://elysiajs.com/patterns/reference-model.html)

### Centralized Model Definitions

```typescript
// Centralized model definitions
export const models = new Elysia({ name: 'models' })
  .model({
    // Base models
    id: t.String({ minLength: 1 }),
    email: t.String({ format: 'email' }),
    password: t.String({ minLength: 8, maxLength: 100 }),
    timestamp: t.String({ format: 'date-time' }),
    
    // User models
    userBase: t.Object({
      id: t.Ref('id'),
      email: t.Ref('email'),
      firstName: t.String({ minLength: 1, maxLength: 50 }),
      lastName: t.Optional(t.String({ maxLength: 50 })),
      emailVerified: t.Boolean(),
      createdAt: t.Ref('timestamp'),
      updatedAt: t.Ref('timestamp')
    }),
    
    userCreate: t.Object({
      email: t.Ref('email'),
      password: t.Ref('password'),
      firstName: t.String({ minLength: 1, maxLength: 50 }),
      lastName: t.Optional(t.String({ maxLength: 50 }))
    }),
    
    userUpdate: t.Partial(
      t.Object({
        firstName: t.String({ minLength: 1, maxLength: 50 }),
        lastName: t.String({ maxLength: 50 }),
        avatar: t.String({ format: 'uri' })
      })
    ),
    
    userAuth: t.Object({
      email: t.Ref('email'),
      password: t.String() // No validation for login
    }),
    
    // Authentication models
    tokenPair: t.Object({
      accessToken: t.String(),
      refreshToken: t.String(),
      expiresIn: t.Number()
    }),
    
    authResponse: t.Object({
      user: t.Ref('userBase'),
      tokens: t.Ref('tokenPair')
    }),
    
    // Session models
    session: t.Object({
      id: t.Ref('id'),
      userId: t.Ref('id'),
      userAgent: t.Optional(t.String()),
      ipAddress: t.Optional(t.String()),
      expiresAt: t.Ref('timestamp'),
      createdAt: t.Ref('timestamp')
    }),
    
    // Error models
    errorResponse: t.Object({
      error: t.Object({
        code: t.String(),
        message: t.String(),
        details: t.Optional(t.Any()),
        timestamp: t.Ref('timestamp'),
        path: t.Optional(t.String())
      })
    }),
    
    validationError: t.Object({
      error: t.Object({
        code: t.Literal('VALIDATION_ERROR'),
        message: t.String(),
        details: t.Array(t.Object({
          field: t.String(),
          message: t.String(),
          received: t.Any()
        }))
      })
    }),
    
    // Pagination models
    paginationQuery: t.Object({
      page: t.Optional(t.Numeric({ minimum: 1 })),
      limit: t.Optional(t.Numeric({ minimum: 1, maximum: 100 })),
      sort: t.Optional(t.String()),
      order: t.Optional(t.Union([t.Literal('asc'), t.Literal('desc')]))
    }),
    
    paginatedResponse: t.Object({
      data: t.Array(t.Any()),
      meta: t.Object({
        total: t.Number(),
        page: t.Number(),
        limit: t.Number(),
        totalPages: t.Number()
      })
    })
  })
  .as('global');

// Usage across multiple route files
export const userRoutes = new Elysia({ prefix: '/users' })
  .use(models)
  .use(authService)
  .post('/', async ({ body, authService }) => {
    const user = await authService.createUser(body);
    return { user };
  }, {
    body: 'userCreate',
    response: {
      201: t.Object({ user: t.Ref('userBase') }),
      400: 'validationError',
      409: 'errorResponse'
    }
  })
  .get('/:id', async ({ params, db }) => {
    const user = await db.user.findUnique({ where: { id: params.id } });
    if (!user) throw new Error('User not found');
    return { user };
  }, {
    params: t.Object({ id: t.Ref('id') }),
    response: {
      200: t.Object({ user: t.Ref('userBase') }),
      404: 'errorResponse'
    }
  })
  .patch('/:id', async ({ params, body, authService }) => {
    const user = await authService.updateUser(params.id, body);
    return { user };
  }, {
    params: t.Object({ id: t.Ref('id') }),
    body: 'userUpdate',
    response: {
      200: t.Object({ user: t.Ref('userBase') }),
      404: 'errorResponse',
      400: 'validationError'
    }
  })
  .get('/', ({ query, db }) => getUsersPaginated(query), {
    query: 'paginationQuery',
    response: {
      200: 'paginatedResponse'
    }
  });
```

## Enhanced Lifecycle Example with Advanced Patterns

```typescript
export const securityPlugin = new Elysia({ name: 'security' })
  .onStart(() => {
    logger.info('Security plugin initialized');
  })
  .onTransform(({ request, headers }) => {
    // Log all requests for security monitoring
    logger.debug('Request received', {
      method: request.method,
      url: request.url,
      userAgent: headers['user-agent'],
      ip: headers['x-forwarded-for']
    });
  })
  .derive(({ headers, request }) => ({
    // Security context for all routes
    clientIp: headers['x-forwarded-for'] || headers['x-real-ip'] || 'unknown',
    userAgent: headers['user-agent'] || 'unknown',
    isSecureConnection: request.url.startsWith('https://')
  }))
  .macro(({ onBeforeHandle }) => ({
    // Custom security macro
    requireSecure(enabled: boolean) {
      if (!enabled) return;
      return onBeforeHandle(({ isSecureConnection, error }) => {
        if (!isSecureConnection && process.env.NODE_ENV === 'production') {
          return error(400, 'HTTPS required');
        }
      });
    },
    rateLimit(options: { max: number; window: number }) {
      return onBeforeHandle(async ({ clientIp, error }) => {
        const isAllowed = await checkRateLimit(clientIp, options);
        if (!isAllowed) {
          return error(429, 'Rate limit exceeded');
        }
      });
    }
  }))
  .onResponse(({ request, set, response }) => {
    // Log responses for monitoring
    logger.info('Response sent', {
      method: request.method,
      url: request.url,
      status: set.status,
      responseTime: Date.now() - request.timestamp
    });
    
    // Add security headers
    set.headers['X-Content-Type-Options'] = 'nosniff';
    set.headers['X-Frame-Options'] = 'DENY';
    set.headers['X-XSS-Protection'] = '1; mode=block';
  })
  .onError(({ error, code, set, request }) => {
    // Security-focused error logging
    logger.error('Request failed', {
      error: error.message,
      code,
      method: request.method,
      url: request.url,
      stack: error.stack
    });
    
    // Don't leak error details in production
    if (process.env.NODE_ENV === 'production') {
      set.headers['Cache-Control'] = 'no-store';
      return {
        error: {
          code: 'INTERNAL_ERROR',
          message: 'An error occurred'
        }
      };
    }
  })
  .as('global'); // Apply security to all routes

// Usage with validation and lifecycle
export const authRoutes = new Elysia({ prefix: '/auth' })
  .use(securityPlugin)
  .use(userService)
  .post('/login', async ({ body, clientIp, userAgent }) => {
    // Security context available from plugin
    await logLoginAttempt(body.email, clientIp, userAgent);
    return await authenticateUser(body);
  }, {
    body: 'userAuth',
    requireSecure: true,
    rateLimit: { max: 5, window: 900000 }, // 5 attempts per 15 minutes
    response: {
      200: 'authResponse',
      401: 'validationError',
      429: 'validationError'
    }
  });
```

## Lifecycle Hooks and Patterns

- Use `guard` for applying middleware to route groups with scoped protection
- Use `resolve`/`derive` for computed properties available in context
- Use `macro` for custom reusable hooks and complex authorization patterns
- Use `beforeHandle` for authentication/authorization checks
- Use `onTransform` for request logging and data transformation
- Use `onError` for centralized error handling
- Use `onResponse` for response logging and modification
- Use `onStart`/`onStop` for application lifecycle management
- Use `decorate` for adding methods and services to context
- Use dependency injection patterns for service management

## Best Practices

1. **Use Named Plugins**: Always provide a `name` property for plugins to enable deduplication and better debugging
2. **Proper Scoping**: Apply `.as('scoped')` or `.as('global')` appropriately for lifecycle isolation
3. **Service Separation**: Create separate plugins for different concerns (database, email, auth, etc.)
4. **Dependency Management**: Use `decorate`, `derive`, and `resolve` for clean dependency injection
5. **Type Safety**: Leverage TypeScript and schema validation for better development experience
6. **Error Handling**: Implement comprehensive error handling with proper logging and user-friendly messages
7. **Performance**: Use caching, connection pooling, and efficient query patterns
8. **Security**: Apply appropriate security measures at plugin level for reusability
