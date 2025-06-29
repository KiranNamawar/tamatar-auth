# GitHub Copilot Instructions for Tamatar Auth

This file provides context and instructions for GitHub Copilot to better assist with the Tamatar Auth microservice development.

## Quick Reference

This instruction set has been split into focused, modular files for better organization and maintainability. Each file covers specific aspects of the project:

### Core Instructions
- **[Project Overview](./instructions/project-overview.md)** - Project summary, architecture patterns, and file structure
- **[Documentation References](./instructions/documentation-references.md)** - Key documentation files and their purposes

### Elysia.js Patterns & Best Practices
- **[Core Patterns](./instructions/elysia-core-patterns.md)** - Essential Elysia.js concepts (plugins, handlers, validation, lifecycle)
- **[Advanced Patterns](./instructions/elysia-advanced-patterns.md)** - Guards, macros, dependency injection, and complex scenarios
- **[Security & Performance Plugins](./instructions/security-performance-plugins.md)** - CORS, JWT, Bearer, rate limiting, and security headers

### Development Standards
- **[TypeScript Standards](./instructions/typescript-standards.md)** - Coding standards, naming conventions, and type safety
- **[Error Handling Patterns](./instructions/error-handling-patterns.md)** - Custom errors, centralized handling, and Elysia.js error patterns
- **[Testing Strategies](./instructions/testing-strategies.md)** - Unit, integration, e2e, and security testing approaches

### Data & Configuration
- **[Database Patterns](./instructions/database-patterns.md)** - Prisma usage, transactions, and database best practices
- **[Environment & Config](./instructions/environment-config.md)** - Environment variables, secrets, and configuration management

## Key Principles

When suggesting code for this project, always consider:

1. **Modern Elysia.js Patterns**: Use the latest Elysia.js idioms with proper plugin architecture and lifecycle management
2. **Type Safety**: Leverage TypeScript and TypeBox for comprehensive type safety
3. **Security First**: Implement proper authentication, authorization, input validation, and security headers
4. **Testing**: Include appropriate tests for new functionality
5. **Documentation**: Reference the official [Elysia.js documentation](https://elysiajs.com/) for current best practices

## Environment Context

- **Runtime**: Bun (fast JavaScript runtime)
- **Framework**: Elysia.js (TypeScript web framework)
- **Database**: PostgreSQL with Prisma ORM
- **Authentication**: JWT tokens with session management
- **Email**: Resend with React Email templates
- **Testing**: Bun test framework
- **Code Quality**: Biome for linting and formatting


