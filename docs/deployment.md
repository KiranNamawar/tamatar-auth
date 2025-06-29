# Deployment Guide

This guide covers deploying the Tamatar Auth microservice to various environments including Docker, Kubernetes, and cloud platforms.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Docker Deployment](#docker-deployment)
- [Kubernetes Deployment](#kubernetes-deployment)
- [Cloud Platform Deployment](#cloud-platform-deployment)
- [Environment Configuration](#environment-configuration)
- [Health Checks](#health-checks)
- [Monitoring and Logging](#monitoring-and-logging)
- [Scaling Considerations](#scaling-considerations)
- [Backup and Recovery](#backup-and-recovery)
- [Troubleshooting](#troubleshooting)

## Prerequisites

Before deploying, ensure you have:

- A PostgreSQL database instance
- Environment variables configured (see [Configuration Guide](./configuration.md))
- SSL certificates for HTTPS (production)
- Monitoring and logging infrastructure
- Backup strategy for the database

## Docker Deployment

### Dockerfile

Create a `Dockerfile` in the project root:

```dockerfile
# Use the official Bun image
FROM oven/bun:1-alpine as base

WORKDIR /app

# Install dependencies
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production

# Copy source code
COPY . .

# Generate Prisma client
RUN bunx prisma generate

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S bun -u 1001

# Change ownership of the app directory
RUN chown -R bun:nodejs /app
USER bun

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:3000/health || exit 1

# Start the application
CMD ["bun", "start"]
```

### Docker Compose

Create a `docker-compose.yml` for local development:

```yaml
version: '3.8'

services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - DATABASE_URL=postgresql://user:password@db:5432/tamatar_auth
      - JWT_SECRET=your-secret-here
      - RESEND_API_KEY=your-key-here
    depends_on:
      db:
        condition: service_healthy
    restart: unless-stopped

  db:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: tamatar_auth
      POSTGRES_USER: user
      POSTGRES_PASSWORD: password
    volumes:
      - postgres_data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U user -d tamatar_auth"]
      interval: 10s
      timeout: 5s
      retries: 5
    restart: unless-stopped

volumes:
  postgres_data:
```

### Building and Running

```bash
# Build the image
docker build -t tamatar-auth:latest .

# Run with Docker Compose
docker-compose up -d

# Check logs
docker-compose logs -f app

# Run database migrations
docker-compose exec app bunx prisma migrate deploy
```

## Kubernetes Deployment

### Namespace

```yaml
# namespace.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: tamatar-auth
```

### ConfigMap

```yaml
# configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: tamatar-auth-config
  namespace: tamatar-auth
data:
  NODE_ENV: "production"
  LOG_LEVEL: "info"
  PORT: "3000"
```

### Secret

```yaml
# secret.yaml
apiVersion: v1
kind: Secret
metadata:
  name: tamatar-auth-secrets
  namespace: tamatar-auth
type: Opaque
stringData:
  DATABASE_URL: "postgresql://user:password@postgres:5432/tamatar_auth"
  JWT_SECRET: "your-jwt-secret-here"
  RESEND_API_KEY: "your-resend-api-key"
```

### Deployment

```yaml
# deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: tamatar-auth
  namespace: tamatar-auth
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
      - name: tamatar-auth
        image: tamatar-auth:latest
        ports:
        - containerPort: 3000
        env:
        - name: PORT
          valueFrom:
            configMapKeyRef:
              name: tamatar-auth-config
              key: PORT
        - name: NODE_ENV
          valueFrom:
            configMapKeyRef:
              name: tamatar-auth-config
              key: NODE_ENV
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: tamatar-auth-secrets
              key: DATABASE_URL
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: tamatar-auth-secrets
              key: JWT_SECRET
        - name: RESEND_API_KEY
          valueFrom:
            secretKeyRef:
              name: tamatar-auth-secrets
              key: RESEND_API_KEY
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
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
```

### Service

```yaml
# service.yaml
apiVersion: v1
kind: Service
metadata:
  name: tamatar-auth-service
  namespace: tamatar-auth
spec:
  selector:
    app: tamatar-auth
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: ClusterIP
```

### Ingress

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: tamatar-auth-ingress
  namespace: tamatar-auth
  annotations:
    nginx.ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - auth.tamatar.com
    secretName: tamatar-auth-tls
  rules:
  - host: auth.tamatar.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: tamatar-auth-service
            port:
              number: 80
```

### Horizontal Pod Autoscaler

```yaml
# hpa.yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: tamatar-auth-hpa
  namespace: tamatar-auth
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: tamatar-auth
  minReplicas: 3
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
```

## Cloud Platform Deployment

### AWS ECS

```yaml
# task-definition.json
{
  "family": "tamatar-auth",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskExecutionRole",
  "taskRoleArn": "arn:aws:iam::ACCOUNT:role/ecsTaskRole",
  "containerDefinitions": [
    {
      "name": "tamatar-auth",
      "image": "your-account.dkr.ecr.region.amazonaws.com/tamatar-auth:latest",
      "portMappings": [
        {
          "containerPort": 3000,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "NODE_ENV",
          "value": "production"
        }
      ],
      "secrets": [
        {
          "name": "DATABASE_URL",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:tamatar-auth/db-url"
        },
        {
          "name": "JWT_SECRET",
          "valueFrom": "arn:aws:secretsmanager:region:account:secret:tamatar-auth/jwt-secret"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/tamatar-auth",
          "awslogs-region": "us-east-1",
          "awslogs-stream-prefix": "ecs"
        }
      },
      "healthCheck": {
        "command": [
          "CMD-SHELL",
          "curl -f http://localhost:3000/health || exit 1"
        ],
        "interval": 30,
        "timeout": 5,
        "retries": 3,
        "startPeriod": 60
      }
    }
  ]
}
```

### Google Cloud Run

```yaml
# cloudrun.yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: tamatar-auth
  namespace: default
  annotations:
    run.googleapis.com/ingress: all
spec:
  template:
    metadata:
      annotations:
        autoscaling.knative.dev/maxScale: "10"
        run.googleapis.com/cpu-throttling: "false"
        run.googleapis.com/execution-environment: gen2
    spec:
      containerConcurrency: 1000
      timeoutSeconds: 300
      containers:
      - image: gcr.io/PROJECT_ID/tamatar-auth:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: production
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: tamatar-auth-secrets
              key: database-url
        resources:
          limits:
            cpu: 1000m
            memory: 512Mi
        livenessProbe:
          httpGet:
            path: /health
          initialDelaySeconds: 30
          periodSeconds: 10
```

## Environment Configuration

### Production Environment Variables

```bash
# Required
NODE_ENV=production
PORT=3000
DATABASE_URL=postgresql://user:password@host:5432/tamatar_auth
JWT_SECRET=your-secure-jwt-secret-here
RESEND_API_KEY=your-resend-api-key

# Optional
LOG_LEVEL=info
JWT_EXPIRES_IN=7d
CORS_ORIGIN=https://yourdomain.com
RATE_LIMIT_MAX=100
RATE_LIMIT_WINDOW=900000
```

### Using External Secret Management

#### AWS Secrets Manager

```typescript
// config/secrets.ts
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

const client = new SecretsManagerClient({ region: "us-east-1" });

export async function getSecret(secretName: string): Promise<string> {
  try {
    const command = new GetSecretValueCommand({ SecretId: secretName });
    const response = await client.send(command);
    return response.SecretString || "";
  } catch (error) {
    console.error(`Failed to retrieve secret ${secretName}:`, error);
    throw error;
  }
}
```

#### Kubernetes Secrets

```bash
# Create secrets from files
kubectl create secret generic tamatar-auth-secrets \
  --from-file=database-url=./secrets/database-url \
  --from-file=jwt-secret=./secrets/jwt-secret \
  --namespace=tamatar-auth
```

## Health Checks

### Application Health Endpoint

```typescript
// src/routes/health.ts
import { Elysia } from "elysia";
import { db } from "../lib/db/prisma";

export const healthRoutes = new Elysia({ prefix: "/health" })
  .get("/", async () => {
    try {
      // Check database connection
      await db.$queryRaw`SELECT 1`;
      
      return {
        status: "healthy",
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: process.env.npm_package_version || "unknown"
      };
    } catch (error) {
      return {
        status: "unhealthy",
        timestamp: new Date().toISOString(),
        error: error.message
      };
    }
  })
  .get("/ready", async () => {
    // Readiness check - more comprehensive
    const checks = await Promise.allSettled([
      db.$queryRaw`SELECT 1`, // Database
      fetch("https://api.resend.com/emails", { 
        method: "HEAD",
        headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}` }
      }) // Email service
    ]);

    const allHealthy = checks.every(check => check.status === "fulfilled");
    
    return {
      status: allHealthy ? "ready" : "not ready",
      checks: checks.map((check, index) => ({
        name: ["database", "email_service"][index],
        status: check.status === "fulfilled" ? "healthy" : "unhealthy"
      }))
    };
  });
```

## Monitoring and Logging

### Prometheus Metrics

```typescript
// src/lib/metrics.ts
import { register, Counter, Histogram, Gauge } from "prom-client";

export const httpRequestsTotal = new Counter({
  name: "http_requests_total",
  help: "Total number of HTTP requests",
  labelNames: ["method", "route", "status_code"],
});

export const httpRequestDuration = new Histogram({
  name: "http_request_duration_seconds",
  help: "Duration of HTTP requests in seconds",
  labelNames: ["method", "route"],
  buckets: [0.1, 0.5, 1, 2, 5],
});

export const activeConnections = new Gauge({
  name: "active_connections",
  help: "Number of active connections",
});

// Export metrics endpoint
export const metricsHandler = () => register.metrics();
```

### Structured Logging

```typescript
// src/lib/logger.ts
import { pino } from "pino";

export const logger = pino({
  level: process.env.LOG_LEVEL || "info",
  transport: process.env.NODE_ENV === "development" ? {
    target: "pino-pretty",
    options: {
      colorize: true,
      translateTime: "SYS:standard",
    },
  } : undefined,
  formatters: {
    level: (label) => ({ level: label }),
  },
  timestamp: pino.stdTimeFunctions.isoTime,
});
```

## Scaling Considerations

### Horizontal Scaling

- **Stateless Design**: Ensure the application is stateless for easy horizontal scaling
- **Session Storage**: Use external session storage (Redis) instead of in-memory
- **Database Connections**: Configure connection pooling appropriately
- **Load Balancing**: Use sticky sessions if required, or ensure complete statelessness

### Vertical Scaling

- **Memory**: Monitor memory usage and adjust limits based on concurrent users
- **CPU**: Profile CPU usage during peak loads
- **Database**: Scale database separately based on read/write patterns

### Caching Strategy

```typescript
// src/lib/cache.ts
import Redis from "ioredis";

const redis = new Redis(process.env.REDIS_URL);

export class CacheService {
  static async get<T>(key: string): Promise<T | null> {
    try {
      const value = await redis.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      console.error("Cache get error:", error);
      return null;
    }
  }

  static async set(key: string, value: any, ttl: number = 3600): Promise<void> {
    try {
      await redis.setex(key, ttl, JSON.stringify(value));
    } catch (error) {
      console.error("Cache set error:", error);
    }
  }

  static async del(key: string): Promise<void> {
    try {
      await redis.del(key);
    } catch (error) {
      console.error("Cache delete error:", error);
    }
  }
}
```

## Backup and Recovery

### Database Backup

```bash
#!/bin/bash
# backup.sh

# Database backup
pg_dump $DATABASE_URL | gzip > "backup-$(date +%Y%m%d-%H%M%S).sql.gz"

# Upload to S3
aws s3 cp "backup-$(date +%Y%m%d-%H%M%S).sql.gz" s3://your-backup-bucket/

# Cleanup old backups (keep last 30 days)
find . -name "backup-*.sql.gz" -mtime +30 -delete
```

### Disaster Recovery Plan

1. **Database Recovery**: Restore from latest backup
2. **Application Deployment**: Deploy from tagged container image
3. **Configuration**: Restore environment variables and secrets
4. **Verification**: Run health checks and smoke tests
5. **DNS**: Update DNS if deploying to new infrastructure

## Troubleshooting

### Common Issues

#### Application Won't Start

```bash
# Check logs
docker logs container_id
kubectl logs deployment/tamatar-auth -n tamatar-auth

# Common causes:
# - Missing environment variables
# - Database connection issues
# - Port conflicts
# - Resource limits
```

#### Database Connection Issues

```bash
# Test database connectivity
docker exec -it container_id bunx prisma db pull

# Check database logs
kubectl logs postgres-pod -n tamatar-auth
```

#### High Memory Usage

```bash
# Check memory usage
kubectl top pods -n tamatar-auth

# Scale up if needed
kubectl scale deployment tamatar-auth --replicas=5 -n tamatar-auth
```

#### SSL Certificate Issues

```bash
# Check certificate expiry
openssl s_client -connect auth.tamatar.com:443 -servername auth.tamatar.com

# Renew certificate (cert-manager)
kubectl delete certificaterequest -n tamatar-auth --all
```

### Debugging Tools

```bash
# Enable debug logging
export LOG_LEVEL=debug

# Database query logging
export DATABASE_LOG_QUERIES=true

# Performance profiling
export NODE_ENV=production
export ENABLE_PROFILING=true
```

### Emergency Procedures

1. **Service Down**: Check health endpoints, restart pods/containers
2. **Database Issues**: Switch to read-only mode, restore from backup
3. **Security Incident**: Revoke all tokens, force password resets
4. **High Load**: Scale horizontally, enable rate limiting

For additional support, refer to the [Security Guide](./security.md) and [Error Handling Guide](./error-handling.md).
