import { Prisma } from "../../generated/prisma";

export class DatabaseError extends Error {
	constructor(
		message: string,
		public cause?: unknown,
	) {
		super(message);
		this.name = "DatabaseError";
	}
}

export class DuplicateError extends DatabaseError {
	constructor(field: string, value: string) {
		super(`A record with ${field} '${value}' already exists`);
		this.name = "DuplicateError";
	}
}

export class NotFoundError extends DatabaseError {
	constructor(resource: string, identifier?: string) {
		super(
			identifier
				? `${resource} with identifier '${identifier}' not found`
				: `${resource} not found`,
		);
		this.name = "NotFoundError";
	}
}

export class ValidationError extends DatabaseError {
	constructor(message: string) {
		super(message);
		this.name = "ValidationError";
	}
}

export class ConflictError extends DatabaseError {
	constructor(
		message: string,
		public details?: unknown,
	) {
		super(message);
		this.name = "ConflictError";
	}
}

export class AuthenticationError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "AuthenticationError";
	}
}

export function handlePrismaError(error: unknown): never {
	if (error instanceof Prisma.PrismaClientKnownRequestError) {
		switch (error.code) {
			case "P2002": {
				// Unique constraint violation
				const target = error.meta?.target as string[] | undefined;
				const field = target?.[0] || "field";
				throw new DuplicateError(field, "provided value");
			}

			case "P2025":
				// Record not found
				throw new NotFoundError("Record");

			case "P2003":
				// Foreign key constraint violation
				throw new ValidationError("Foreign key constraint failed");

			case "P2004":
				// Constraint failed
				throw new ValidationError("Database constraint failed");

			default:
				console.error("Prisma error:", error);
				throw new DatabaseError("Database operation failed", error);
		}
	}

	if (error instanceof Prisma.PrismaClientValidationError) {
		throw new ValidationError("Invalid data provided to database");
	}

	if (error instanceof Prisma.PrismaClientInitializationError) {
		throw new DatabaseError("Database connection failed", error);
	}

	// Re-throw if it's already our custom error
	if (error instanceof DatabaseError) {
		throw error;
	}

	// Unknown error
	console.error("Unknown database error:", error);
	throw new DatabaseError("An unexpected database error occurred", error);
}

// Utility to wrap repository operations with error handling
export function withErrorHandling<T extends any[], R>(
	fn: (...args: T) => Promise<R>,
) {
	return async (...args: T): Promise<R> => {
		try {
			return await fn(...args);
		} catch (error) {
			handlePrismaError(error);
		}
	};
}
