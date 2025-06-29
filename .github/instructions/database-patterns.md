# Database Patterns and Best Practices

This guide covers database operation patterns, Prisma usage, and best practices for the Tamatar Auth microservice.

## Database Operations with Prisma

### Transaction Patterns

Always use transactions for related operations to maintain data consistency:

```typescript
// ✅ Good - Using transaction for related operations
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

// ✅ Good - Complex transaction with error handling
export async function authenticateAndCreateSession(
  email: string, 
  password: string,
  sessionData: SessionCreateData
) {
  return await db.$transaction(async (tx) => {
    // Verify user credentials
    const user = await tx.user.findUnique({ 
      where: { email },
      select: { id: true, password: true, emailVerified: true }
    });
    
    if (!user || !await bcrypt.compare(password, user.password)) {
      throw new AuthenticationError('Invalid credentials');
    }
    
    if (!user.emailVerified) {
      throw new EmailNotVerifiedError();
    }
    
    // Update last login
    await tx.user.update({
      where: { id: user.id },
      data: { lastLoginAt: new Date() }
    });
    
    // Create session
    const session = await tx.session.create({
      data: {
        userId: user.id,
        ...sessionData,
        expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)
      }
    });
    
    return { user, session };
  });
}
```

### Repository Pattern

Implement repository pattern for clean data access:

```typescript
// src/lib/db/repositories/user.ts
export class UserRepository {
  constructor(private db: PrismaClient) {}

  async create(data: Prisma.UserCreateInput): Promise<User> {
    return await this.db.user.create({
      data,
      select: this.userSelectFields
    });
  }

  async findById(id: string): Promise<User | null> {
    return await this.db.user.findUnique({
      where: { id },
      select: this.userSelectFields
    });
  }

  async findByEmail(email: string): Promise<User | null> {
    return await this.db.user.findUnique({
      where: { email: email.toLowerCase() },
      select: this.userSelectFields
    });
  }

  async updateLastLogin(id: string): Promise<User> {
    return await this.db.user.update({
      where: { id },
      data: { lastLoginAt: new Date() },
      select: this.userSelectFields
    });
  }

  async softDelete(id: string): Promise<User> {
    return await this.db.user.update({
      where: { id },
      data: { 
        isActive: false,
        deletedAt: new Date()
      },
      select: this.userSelectFields
    });
  }

  private get userSelectFields() {
    return {
      id: true,
      email: true,
      firstName: true,
      lastName: true,
      avatar: true,
      emailVerified: true,
      isActive: true,
      createdAt: true,
      updatedAt: true,
      // Never select password in responses
      password: false
    };
  }

  async findMany(params: {
    skip?: number;
    take?: number;
    where?: Prisma.UserWhereInput;
    orderBy?: Prisma.UserOrderByWithRelationInput;
  }): Promise<{ users: User[]; total: number }> {
    const [users, total] = await Promise.all([
      this.db.user.findMany({
        ...params,
        select: this.userSelectFields
      }),
      this.db.user.count({ where: params.where })
    ]);
    
    return { users, total };
  }
}

// Usage in Elysia service
export const userService = new Elysia({ name: 'user-service' })
  .use(databaseService)
  .derive(({ db }) => ({
    userRepo: new UserRepository(db)
  }))
  .as('scoped');
```

### Query Optimization

Use proper selection and indexing for performance:

```typescript
// ✅ Good - Select only needed fields
const user = await db.user.findUnique({
  where: { id: userId },
  select: {
    id: true,
    email: true,
    firstName: true,
    lastName: true,
    emailVerified: true
    // Don't select password, createdAt, updatedAt unless needed
  }
});

// ✅ Good - Use includes for relations
const userWithSessions = await db.user.findUnique({
  where: { id: userId },
  include: {
    sessions: {
      where: { 
        isValid: true,
        expiresAt: { gt: new Date() }
      },
      orderBy: { lastActivityAt: 'desc' },
      take: 10
    }
  }
});

// ✅ Good - Batch operations for efficiency
const userIds = ['id1', 'id2', 'id3'];
const users = await db.user.findMany({
  where: { 
    id: { in: userIds },
    isActive: true
  },
  select: userSelectFields
});

// ✅ Good - Use aggregations for counting
const stats = await db.user.aggregate({
  where: { 
    createdAt: { gte: startDate },
    emailVerified: true
  },
  _count: true,
  _min: { createdAt: true },
  _max: { createdAt: true }
});
```

### Error Handling

Handle database errors gracefully:

```typescript
export class DatabaseService {
  async safeOperation<T>(operation: () => Promise<T>): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError) {
        switch (error.code) {
          case 'P2002':
            throw new ConflictError('Resource already exists', error.meta?.target);
          case 'P2025':
            throw new NotFoundError('Resource not found');
          case 'P2003':
            throw new ValidationError('Foreign key constraint failed');
          default:
            logger.error('Database error', { error, code: error.code });
            throw new DatabaseError('Database operation failed');
        }
      }
      
      if (error instanceof Prisma.PrismaClientValidationError) {
        throw new ValidationError('Invalid data provided');
      }
      
      logger.error('Unexpected database error', { error });
      throw new DatabaseError('Unexpected database error');
    }
  }

  async findUserSafely(email: string): Promise<User | null> {
    return this.safeOperation(async () => {
      return await db.user.findUnique({
        where: { email: email.toLowerCase().trim() }
      });
    });
  }
}
```

## Schema Design Patterns

### Indexing Strategy

Ensure proper indexes for performance:

```prisma
model User {
  id              String   @id @default(cuid())
  email           String   @unique @db.VarChar(255)
  username        String   @unique @db.VarChar(30)
  emailVerified   Boolean  @default(false)
  isActive        Boolean  @default(true)
  createdAt       DateTime @default(now())
  updatedAt       DateTime @updatedAt

  // Composite indexes for common queries
  @@index([emailVerified, isActive], name: "idx_user_status")
  @@index([createdAt], name: "idx_user_created")
  @@index([isActive, updatedAt], name: "idx_user_active_updated")
  @@map("users")
}

model Session {
  id             String   @id @default(cuid())
  userId         String
  isValid        Boolean  @default(true)
  expiresAt      DateTime
  lastActivityAt DateTime @default(now())
  createdAt      DateTime @default(now())

  user User @relation(fields: [userId], references: [id], onDelete: Cascade)

  // Performance indexes
  @@index([userId, isValid, expiresAt], name: "idx_session_user_valid")
  @@index([expiresAt], name: "idx_session_expires")
  @@index([lastActivityAt], name: "idx_session_activity")
  @@map("sessions")
}
```

### Soft Delete Pattern

Implement soft deletes for audit and recovery:

```typescript
// Extend Prisma model with soft delete fields
model User {
  // ... other fields
  isActive  Boolean   @default(true)
  deletedAt DateTime?
  deletedBy String?   // Who performed the deletion
  
  @@map("users")
}

// Soft delete service
export class SoftDeleteService {
  async softDelete(
    model: string, 
    id: string, 
    deletedBy?: string
  ): Promise<any> {
    const updateData = {
      isActive: false,
      deletedAt: new Date(),
      ...(deletedBy && { deletedBy })
    };
    
    // Use dynamic model access
    return await (db as any)[model].update({
      where: { id },
      data: updateData
    });
  }
  
  async restore(model: string, id: string): Promise<any> {
    return await (db as any)[model].update({
      where: { id },
      data: {
        isActive: true,
        deletedAt: null,
        deletedBy: null
      }
    });
  }
  
  // Middleware to filter soft-deleted records
  static addSoftDeleteFilter() {
    db.$use(async (params, next) => {
      // Apply to read operations
      if (params.action === 'findUnique' || params.action === 'findFirst') {
        params.args.where = {
          ...params.args.where,
          isActive: true
        };
      }
      
      if (params.action === 'findMany') {
        if (params.args.where) {
          if (params.args.where.isActive === undefined) {
            params.args.where.isActive = true;
          }
        } else {
          params.args.where = { isActive: true };
        }
      }
      
      return next(params);
    });
  }
}
```

## Database Connection Management

### Connection Pool Configuration

```typescript
// src/lib/db/connection.ts
export class DatabaseConnection {
  private static instance: PrismaClient;
  
  static getInstance(): PrismaClient {
    if (!this.instance) {
      this.instance = new PrismaClient({
        log: process.env.NODE_ENV === 'development' 
          ? ['query', 'info', 'warn', 'error']
          : ['error'],
        errorFormat: 'colorless',
        datasources: {
          db: {
            url: process.env.DATABASE_URL
          }
        }
      });
      
      // Connection lifecycle management
      this.setupLifecycleHooks();
    }
    
    return this.instance;
  }
  
  private static setupLifecycleHooks(): void {
    // Graceful shutdown
    process.on('SIGTERM', async () => {
      logger.info('SIGTERM received, closing database connection');
      await this.instance.$disconnect();
      process.exit(0);
    });
    
    process.on('SIGINT', async () => {
      logger.info('SIGINT received, closing database connection');
      await this.instance.$disconnect();
      process.exit(0);
    });
    
    // Handle uncaught exceptions
    process.on('uncaughtException', async (error) => {
      logger.error('Uncaught exception', { error });
      await this.instance.$disconnect();
      process.exit(1);
    });
  }
  
  static async healthCheck(): Promise<boolean> {
    try {
      await this.getInstance().$queryRaw`SELECT 1`;
      return true;
    } catch (error) {
      logger.error('Database health check failed', { error });
      return false;
    }
  }
  
  static async getConnectionInfo(): Promise<any> {
    const result = await this.getInstance().$queryRaw`
      SELECT 
        count(*) as total_connections,
        count(*) FILTER (WHERE state = 'active') as active_connections,
        count(*) FILTER (WHERE state = 'idle') as idle_connections
      FROM pg_stat_activity 
      WHERE datname = current_database()
    `;
    
    return result;
  }
}

// Elysia database plugin
export const databasePlugin = new Elysia({ name: 'database' })
  .decorate({
    db: DatabaseConnection.getInstance()
  })
  .onStart(async ({ db }) => {
    logger.info('🚀 Database connection established');
    await db.$connect();
    
    // Apply middleware
    SoftDeleteService.addSoftDeleteFilter();
  })
  .onStop(async ({ db }) => {
    logger.info('📴 Closing database connection');
    await db.$disconnect();
  })
  .as('global');
```

## Migration and Seeding

### Migration Best Practices

```typescript
// Always use descriptive migration names
// bunx prisma migrate dev --name add_user_profile_fields

// Example migration with data transformation
-- Add new column with default value
ALTER TABLE "users" ADD COLUMN "full_name" VARCHAR(100);

-- Populate from existing data
UPDATE "users" SET "full_name" = CONCAT("firstName", ' ', "lastName") 
WHERE "firstName" IS NOT NULL;

-- Add constraints after data population
ALTER TABLE "users" ALTER COLUMN "full_name" SET NOT NULL;
```

### Database Seeding

```typescript
// prisma/seed.ts
import { PrismaClient } from '@prisma/client';
import { hash } from 'bcryptjs';

const prisma = new PrismaClient();

async function main() {
  console.log('🌱 Starting database seed...');
  
  // Create admin user
  const adminUser = await prisma.user.upsert({
    where: { email: 'admin@tamatar.dev' },
    update: {},
    create: {
      email: 'admin@tamatar.dev',
      username: 'admin',
      firstName: 'Admin',
      lastName: 'User',
      password: await hash('SecureAdminPass123!', 12),
      emailVerified: true,
      isActive: true
    }
  });
  
  console.log(`👤 Created admin user: ${adminUser.email}`);
  
  // Create test users for development
  if (process.env.NODE_ENV === 'development') {
    const testUsers = await Promise.all([
      prisma.user.upsert({
        where: { email: 'test1@example.com' },
        update: {},
        create: {
          email: 'test1@example.com',
          username: 'testuser1',
          firstName: 'Test',
          lastName: 'User1',
          password: await hash('TestPass123!', 12),
          emailVerified: true
        }
      }),
      prisma.user.upsert({
        where: { email: 'test2@example.com' },
        update: {},
        create: {
          email: 'test2@example.com',
          username: 'testuser2',
          firstName: 'Test',
          lastName: 'User2',
          password: await hash('TestPass123!', 12),
          emailVerified: false
        }
      })
    ]);
    
    console.log(`👥 Created ${testUsers.length} test users`);
  }
  
  console.log('✅ Database seed completed');
}

main()
  .catch((e) => {
    console.error('❌ Seeding failed:', e);
    process.exit(1);
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
```

## Performance Monitoring

### Query Performance Tracking

```typescript
// src/lib/db/monitoring.ts
export class DatabaseMonitoring {
  static setupQueryLogging(db: PrismaClient): void {
    db.$use(async (params, next) => {
      const start = Date.now();
      const result = await next(params);
      const end = Date.now();
      const duration = end - start;
      
      // Log slow queries
      if (duration > 1000) { // Queries taking more than 1 second
        logger.warn('Slow query detected', {
          model: params.model,
          action: params.action,
          duration: `${duration}ms`,
          args: params.args
        });
      }
      
      // Metrics collection
      if (process.env.METRICS_ENABLED === 'true') {
        queryDurationHistogram.observe(
          { model: params.model, action: params.action },
          duration / 1000
        );
      }
      
      return result;
    });
  }
  
  static async getQueryStats(): Promise<any[]> {
    return await db.$queryRaw`
      SELECT 
        query,
        calls,
        total_time,
        mean_time,
        rows
      FROM pg_stat_statements 
      ORDER BY total_time DESC 
      LIMIT 10
    `;
  }
}
```

## Best Practices Summary

### Do's ✅

1. **Use transactions** for related operations
2. **Select only needed fields** to reduce bandwidth
3. **Implement proper error handling** for database operations
4. **Use indexes** for frequently queried fields
5. **Implement soft deletes** for audit trails
6. **Use repository pattern** for clean data access
7. **Monitor query performance** and optimize slow queries
8. **Use connection pooling** appropriately
9. **Validate data** at application level before database operations
10. **Use migrations** for schema changes

### Don'ts ❌

1. **Don't select sensitive fields** (like passwords) in responses
2. **Don't ignore database errors** - handle them gracefully
3. **Don't perform multiple single operations** instead of batch operations
4. **Don't forget to add indexes** for foreign keys and frequently queried fields
5. **Don't use raw SQL** unless absolutely necessary
6. **Don't expose Prisma errors** directly to API responses
7. **Don't perform database operations** in loops without batching
8. **Don't forget to clean up** expired sessions and tokens
9. **Don't skip data validation** before database operations
10. **Don't hardcode connection strings** in code

This database pattern guide ensures efficient, secure, and maintainable database operations throughout the Tamatar Auth microservice.
