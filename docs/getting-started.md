# Getting Started
3. **Install dependencies**
   ```bash
   bun install
   
   # Install Elysia.js security and performance plugins
   bun add @elysiajs/cors @elysiajs/jwt @elysiajs/bearer elysia-rate-limit
   ```

4. **Set up environment variables**rerequisites

Before running the Tamatar Auth microservice, ensure you have the following installed:

- [Bun](https://bun.sh/) (v1.0 or later)
- [PostgreSQL](https://postgresql.org/) (v14 or later)
- [Node.js](https://nodejs.org/) (v18 or later) - for email template development
- [Doppler CLI](https://docs.doppler.com/docs/install-cli) - for environment management

## Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd tamatar-auth
   ```

2. **Install dependencies**
   ```bash
   bun install
   ```

3. **Set up environment variables**
   
   Create a `.env` file or use Doppler for environment management:
   ```bash
   # Database
   DATABASE_URL="postgresql://username:password@localhost:5432/tamatar_auth"
   
   # JWT Configuration
   JWT_SECRET="your-super-secret-jwt-key-here"
   
   # Email Service (Resend)
   RESEND_API_KEY="your-resend-api-key"
   
   # Application
   PORT=3000
   NODE_ENV="development"
   ```

4. **Set up the database**
   ```bash
   # Generate Prisma client
   bunx prisma generate
   
   # Run migrations
   bunx prisma migrate dev
   
   # (Optional) Seed the database
   bunx prisma db seed
   ```

## Development

### Starting the Development Server

```bash
# Using Doppler (recommended)
bun run dev

# Or directly with Bun
bun run --watch src/index.ts
```

The server will start on `http://localhost:3000` with hot reloading enabled.

### Available Scripts

```bash
# Development
bun run dev          # Start with Doppler and hot reload
bun run start        # Start production server with Doppler

# Email Development
bun run email        # Start email template development server

# Code Quality
bun run lint         # Run linter with auto-fix
bun run format       # Format code
bun run check        # Run both linting and formatting

# Database
bunx prisma studio   # Open Prisma Studio (database GUI)
bunx prisma generate # Regenerate Prisma client
bunx prisma migrate dev # Run migrations in development

# Plugin Development
bun run dev:plugins  # Test Elysia.js plugins in isolation
```

## Environment Setup

### Using Doppler (Recommended)

1. **Install Doppler CLI**
   ```bash
   # macOS
   brew install dopplerhq/cli/doppler
   
   # Windows (using Scoop)
   scoop install doppler
   
   # Linux
   curl -Ls https://cli.doppler.com/install.sh | sh
   ```

2. **Login to Doppler**
   ```bash
   doppler login
   ```

3. **Set up project**
   ```bash
   doppler setup
   ```

### Using .env File

If not using Doppler, create a `.env` file in the project root:

```env
# Database Configuration
DATABASE_URL="postgresql://username:password@localhost:5432/tamatar_auth"

# JWT Configuration
JWT_SECRET="your-256-bit-secret-key-here"
JWT_EXPIRES_IN="7d"

# Email Service
RESEND_API_KEY="re_your_resend_api_key"
FROM_EMAIL="auth@email.tamatar.dev"

# OAuth (Google)
GOOGLE_CLIENT_ID="your-google-client-id"
GOOGLE_CLIENT_SECRET="your-google-client-secret"

# Application Configuration
PORT=3000
NODE_ENV="development"
CORS_ORIGIN="http://localhost:3000,http://localhost:3001"

# Security
BCRYPT_ROUNDS=12
SESSION_MAX_AGE="7d"
```

## Database Setup

### PostgreSQL Installation

**macOS (using Homebrew):**
```bash
brew install postgresql
brew services start postgresql
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
```

**Windows:**
Download and install from [PostgreSQL official website](https://www.postgresql.org/download/windows/).

### Database Creation

```bash
# Connect to PostgreSQL
psql -U postgres

# Create database
CREATE DATABASE tamatar_auth;

# Create user (optional)
CREATE USER tamatar_user WITH PASSWORD 'secure_password';
GRANT ALL PRIVILEGES ON DATABASE tamatar_auth TO tamatar_user;

# Exit psql
\q
```

### Running Migrations

```bash
# Generate Prisma client
bunx prisma generate

# Run all pending migrations
bunx prisma migrate dev

# Reset database (development only)
bunx prisma migrate reset
```

## Verification

### Health Check

Test if the service is running:
```bash
curl http://localhost:3000/health
```

Expected response:
```json
{
  "status": "ok",
  "timestamp": "2025-06-29T10:30:45.123Z"
}
```

### API Documentation

Visit `http://localhost:3000/swagger` to access the interactive API documentation.

### Database Connection

Test database connectivity:
```bash
bunx prisma studio
```

This opens a web-based database browser at `http://localhost:5555`.

## Docker Setup (Optional)

### Using Docker Compose

Create a `docker-compose.yml` file:

```yaml
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: tamatar_user
      POSTGRES_PASSWORD: secure_password
      POSTGRES_DB: tamatar_auth
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data

  auth-service:
    build: .
    ports:
      - "3000:3000"
    environment:
      DATABASE_URL: "postgresql://tamatar_user:secure_password@postgres:5432/tamatar_auth"
      JWT_SECRET: "your-jwt-secret"
      RESEND_API_KEY: "your-resend-api-key"
    depends_on:
      - postgres

volumes:
  postgres_data:
```

Run with:
```bash
docker-compose up -d
```

## Troubleshooting

### Common Issues

1. **Database Connection Failed**
   - Verify PostgreSQL is running
   - Check DATABASE_URL format
   - Ensure database exists

2. **Port Already in Use**
   ```bash
   # Find process using port 3000
   lsof -i :3000
   
   # Kill the process
   kill -9 <PID>
   ```

3. **Prisma Generate Fails**
   ```bash
   # Clear Prisma cache
   bunx prisma generate --force
   ```

4. **JWT Secret Missing**
   - Ensure JWT_SECRET is set in environment
   - Use a secure, random 256-bit key

### Debug Mode

Enable debug logging:
```bash
DEBUG=* bun run dev
```

## Next Steps

- Review the [API Reference](./api-reference.md) for endpoint documentation
- Read [Error Handling](./error-handling.md) for error management patterns
- Check [Security](./security.md) for security best practices
- See [Configuration](./configuration.md) for advanced configuration options
