// Database layer exports

// Re-export Prisma types for convenience
export type { Prisma, Session, User } from "../../generated/prisma";
// Error handling
export {
	DatabaseError,
	DuplicateError,
	handlePrismaError,
	NotFoundError,
	ValidationError,
	withErrorHandling,
} from "./errors";
export { databasePlugin } from "./plugin";
export { DatabaseConnection } from "./prisma";
export { repositoryPlugin } from "./repositories";
export { SessionRepository } from "./session";
// Repositories
export { UserRepository } from "./user";
