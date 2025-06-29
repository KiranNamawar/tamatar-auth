import { PrismaClient } from "../../generated/prisma";
import { config } from "../config";

class DatabaseConnection {
	private static instance: PrismaClient;

	static getInstance(): PrismaClient {
		if (!DatabaseConnection.instance) {
			const cfg = config.get();

			DatabaseConnection.instance = new PrismaClient({
				log:
					cfg.nodeEnv === "development"
						? ["query", "info", "warn", "error"]
						: ["error"],
				errorFormat: "colorless",
				datasources: {
					db: {
						url: cfg.database.url,
					},
				},
			});

			// Setup lifecycle hooks
			DatabaseConnection.setupLifecycleHooks();
		}

		return DatabaseConnection.instance;
	}

	private static setupLifecycleHooks(): void {
		// Graceful shutdown
		process.on("SIGTERM", async () => {
			console.log("🔌 SIGTERM received, closing database connection");
			await DatabaseConnection.instance.$disconnect();
			process.exit(0);
		});

		process.on("SIGINT", async () => {
			console.log("🔌 SIGINT received, closing database connection");
			await DatabaseConnection.instance.$disconnect();
			process.exit(0);
		});
	}

	static async healthCheck(): Promise<boolean> {
		try {
			await DatabaseConnection.getInstance().$queryRaw`SELECT 1`;
			return true;
		} catch (error) {
			console.error("❌ Database health check failed:", error);
			return false;
		}
	}

	static async connect(): Promise<void> {
		console.log("🔗 Connecting to database...");
		await DatabaseConnection.getInstance().$connect();
		console.log("✅ Database connected successfully");
	}

	static async disconnect(): Promise<void> {
		console.log("🔌 Disconnecting from database...");
		await DatabaseConnection.instance.$disconnect();
		console.log("✅ Database disconnected");
	}
}

const prisma = DatabaseConnection.getInstance();

export default prisma;
export { DatabaseConnection };
