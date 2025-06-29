# Tamatar Auth Microservice Documentation

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Quick Start](./getting-started.md)
- [API Reference](./api-reference.md)
- [Error Handling](./error-handling.md)
- [Authentication & Authorization](./auth-guide.md)
- [Database Design](./database.md)
- [Email Service](./email.md)
- [Configuration](./configuration.md)
- [Deployment](./deployment.md)
- [Security](./security.md)
- [Testing](./testing.md)
- [Contributing](./contributing.md)

## Overview

Tamatar Auth is a centralized authentication microservice designed to handle user authentication and authorization for all Tamatar ecosystem projects. Built with modern technologies and best practices, it provides a secure, scalable, and maintainable authentication solution.

### Key Features

- **JWT-based Authentication**: Secure token-based authentication
- **Session Management**: Comprehensive session tracking and management
- **Email Verification**: Built-in email verification system
- **OAuth Integration**: Google OAuth support (extensible for other providers)
- **RESTful API**: Clean, well-documented REST endpoints
- **Database Agnostic**: Uses Prisma ORM for database operations
- **Type Safety**: Full TypeScript support with generated types
- **API Documentation**: Auto-generated Swagger documentation
- **Email Templates**: React-based email templates with Resend integration

### Technology Stack

- **Runtime**: [Bun](https://bun.sh/) - Fast JavaScript runtime
- **Framework**: [Elysia.js](https://elysiajs.com/) - Fast and type-safe web framework with [plugin architecture](https://elysiajs.com/concept/plugin.html)
- **Database**: PostgreSQL with [Prisma ORM](https://prisma.io/)
- **Authentication**: JWT tokens with session management using [@elysiajs/jwt](https://elysiajs.com/plugins/jwt.html)
- **Email**: [Resend](https://resend.com/) with React Email templates
- **Validation**: [TypeBox](https://elysiajs.com/validation/overview.html) with Elysia's validation system
- **Security**: [CORS](https://elysiajs.com/plugins/cors.html), [Bearer Authentication](https://elysiajs.com/plugins/bearer.html), and [Rate Limiting](https://elysiajs.com/plugins/rate-limit.html)
- **Documentation**: Auto-generated Swagger/OpenAPI with Elysia's schema system
- **Code Quality**: Biome for linting and formatting

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Apps   │    │   Load Balancer │    │   Other Services│
│                 │    │                 │    │                 │
│ - Web App       │◄──►│   (Optional)    │◄──►│ - User Service  │
│ - Mobile App    │    │                 │    │ - Content API   │
│ - Admin Panel   │    │                 │    │ - etc.          │
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         └───────────────────────┼───────────────────────┘
                                 │
                                 ▼
                    ┌─────────────────┐
                    │  Tamatar Auth   │
                    │  Microservice   │
                    │                 │
                    │ - JWT Auth      │
                    │ - Session Mgmt  │
                    │ - User Mgmt     │
                    │ - Email Service │
                    └─────────────────┘
                                 │
                    ┌─────────────────┐
                    │   PostgreSQL    │
                    │   Database      │
                    │                 │
                    │ - Users         │
                    │ - Sessions      │
                    └─────────────────┘
```

## Project Structure

```
tamatar-auth/
├── docs/                     # Documentation
├── prisma/                   # Database schema and migrations
│   ├── schema.prisma        # Database schema
│   └── migrations/          # Database migrations
├── src/
│   ├── index.ts            # Application entry point with Elysia app
│   ├── generated/          # Generated code (Prisma, PrismaBox)
│   ├── routes/             # Route handlers using Elysia patterns
│   ├── middleware/         # Elysia middleware and plugins
│   ├── plugins/            # Custom Elysia plugins
│   └── lib/
│       ├── db/             # Database utilities and repositories
│       ├── email/          # Email service with templates
│       ├── auth/           # Authentication utilities
│       └── validation/     # TypeBox validation schemas
├── package.json
├── tsconfig.json
└── biome.json             # Code formatting and linting
```

## Elysia.js Architecture

The application follows [Elysia.js best practices](https://elysiajs.com/) with:

- **[Plugin Architecture](https://elysiajs.com/concept/plugin.html)**: Modular services with proper scoping and lifecycle management
- **[Handler Context](https://elysiajs.com/concept/handler.html)**: Typed request/response handling with context utilities
- **[Validation System](https://elysiajs.com/validation/overview.html)**: TypeBox-powered schema validation for all endpoints
- **[Lifecycle Hooks](https://elysiajs.com/life-cycle/overview.html)**: Request processing pipeline with authentication and error handling
- **[Dependency Injection](https://elysiajs.com/patterns/dependency-injection.html)**: Service injection using `decorate`, `derive`, and `resolve`
- **[Reference Models](https://elysiajs.com/patterns/reference-model.html)**: Reusable validation schemas across the application

## Getting Started

For detailed setup instructions, see the [Getting Started Guide](./getting-started.md).

## API Endpoints

For complete API documentation, see the [API Reference](./api-reference.md).

### Core Endpoints

- `POST /register` - User registration
- `POST /login` - User authentication
- `POST /logout` - User logout
- `GET /me` - Get current user profile
- `POST /verify-email` - Email verification
- `POST /forgot-password` - Password reset request
- `POST /reset-password` - Password reset

## Contributing

See [Contributing Guide](./contributing.md) for development guidelines and best practices.

## License

This project is part of the Tamatar ecosystem. See the main project for licensing information.
