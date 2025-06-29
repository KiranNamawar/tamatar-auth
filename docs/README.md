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
- **Framework**: [Elysia.js](https://elysiajs.com/) - Fast and type-safe web framework
- **Database**: PostgreSQL with [Prisma ORM](https://prisma.io/)
- **Authentication**: JWT tokens with session management
- **Email**: [Resend](https://resend.com/) with React Email templates
- **Validation**: Elysia's built-in validation with TypeBox
- **Documentation**: Swagger/OpenAPI
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
│   ├── index.ts            # Application entry point
│   ├── generated/          # Generated code (Prisma, TypeBox)
│   └── lib/
│       ├── db/             # Database utilities
│       └── email/          # Email service and templates
├── package.json
├── tsconfig.json
└── biome.json             # Code formatting and linting
```

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
