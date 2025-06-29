# Elysia.js Core Patterns

When suggesting Elysia.js code, always consider the latest patterns from the official documentation:

## Essential Concepts

### Plugin Architecture (https://elysiajs.com/concept/plugin.html)
- Use named plugins (`name: "plugin-name"`) for deduplication and better debugging
- Apply proper scoping with `.as('scoped')` or `.as('global')` for lifecycle isolation
- Separate concerns into reusable service plugins with clear boundaries
- Use encapsulation by default (lifecycle hooks don't leak between plugins)
- Prefer functional plugins over class-based for better tree-shaking and performance
- Use plugin dependencies and ordering when needed for complex setups
- Implement dependency injection patterns with `decorate`, `derive`, and `resolve`

### Route Handlers (https://elysiajs.com/concept/handler.html)
- Destructure context for commonly used properties: `{ body, query, params, headers, set, error }`
- Use async handlers for database operations and external API calls
- Return proper response objects with appropriate status codes
- Leverage context utilities like `set.status`, `set.headers`, and `error()` function
- Handle both synchronous and asynchronous operations appropriately
- Use proper TypeScript typing for handler parameters

### Validation Patterns (https://elysiajs.com/validation/overview.html)
- Define reference models with `.model()` for reusability across routes
- Use TypeBox (`t.*`) for all validation schemas (body, query, params, headers, response)
- Reference models by name in route handlers for consistency and maintainability
- Prefer schema inference over manual typing for better type safety
- Validate request body, query parameters, headers, and cookies as needed
- Define response schemas for API documentation and type safety
- Use error schemas for consistent error response formats
- Implement custom validation with transform and check functions

### Lifecycle Hooks (https://elysiajs.com/life-cycle/overview.html)
- Use `onStart`/`onStop` for application lifecycle management and cleanup
- Use `onTransform` for request preprocessing and logging
- Use `onBeforeHandle` for authentication and authorization checks
- Use `onAfterHandle` for response modification and processing
- Use `onError` for centralized error handling and logging
- Use `onResponse` for response logging and final modifications
- Apply lifecycle hooks at appropriate plugin scopes for proper isolation

## Context Object Patterns

Handler context provides these key properties:

```typescript
interface ElysiaContext {
  body: any;           // Request body (validated if schema provided)
  query: Record<string, string>;  // Query parameters
  params: Record<string, string>; // Path parameters
  headers: Record<string, string>; // Request headers
  set: {               // Response utilities
    status?: number;
    headers: Record<string, string>;
    redirect?: string;
  };
  cookie: {            // Cookie utilities
    [name: string]: {
      value: string;
      set: (options: CookieOptions) => void;
    };
  };
  error: (code: number, message: string) => Response;
  // Plus any resolved values from plugins
}
```

### Best practices for context usage:

```typescript
export const userRoutes = new Elysia({ name: 'user' })
  .resolve(({ headers }) => ({
    // Resolve common values to avoid repetition
    userId: extractUserIdFromToken(headers.authorization)
  }))
  .get('/profile', ({ userId, set }) => {
    // Use resolved values directly
    if (!userId) {
      set.status = 401;
      return { error: 'Unauthorized' };
    }
    return getUserProfile(userId);
  })
  .patch('/profile', async ({ userId, body, set, error }) => {
    if (!userId) return error(401, 'Unauthorized');
    
    try {
      const updated = await updateUserProfile(userId, body);
      set.status = 200;
      return { user: updated };
    } catch (err) {
      return error(400, 'Update failed');
    }
  });
```

## Handler Patterns

```typescript
// Elysia handlers receive a context object with request/response utilities
import { Elysia, t } from "elysia";

// Basic handler with destructured context
export const authRoutes = new Elysia({ 
  prefix: "/auth",
  name: "auth"
})
  .model({
    userAuth: t.Object({
      email: t.String({ format: "email" }),
      password: t.String({ minLength: 8 }),
    })
  })
  .post("/login", async ({ body, set, headers, cookie }) => {
    // Context provides: body, query, params, headers, set, cookie, etc.
    const { email, password } = body;
    
    // Set response status and headers
    set.status = 200;
    set.headers["X-Custom-Header"] = "auth-success";
    
    // Set cookies with options
    cookie.sessionId.set({
      value: "session-token",
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 60 * 60 * 24 * 7 // 7 days
    });
    
    return { token: "jwt-token", user: {} };
  }, {
    body: "userAuth"
  })
  
  // Handler with full context object
  .get("/profile/:id", (context) => {
    const { params, query, headers } = context;
    return { userId: params.id, filter: query.filter };
  })
  
  // Async handler with error handling
  .patch("/profile", async ({ body, set, error }) => {
    try {
      const user = await updateProfile(body);
      return { user };
    } catch (err) {
      // Use error() for custom error responses
      return error(400, "Profile update failed");
    }
  })
  
  // Handler returning different response types
  .get("/avatar/:id", ({ params, set }) => {
    // Return file
    return Bun.file(`./uploads/${params.id}.jpg`);
  })
  
  .get("/redirect", ({ set }) => {
    // Redirect response
    set.redirect = "/dashboard";
  })
  .as('scoped');
```
