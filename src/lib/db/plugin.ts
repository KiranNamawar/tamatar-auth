import { Elysia } from "elysia";
import { configPlugin } from "../config/plugin";
import { DatabaseConnection } from "./prisma";

export const databasePlugin = new Elysia({ name: "database" })
	.use(configPlugin)
	.decorate({
		db: DatabaseConnection.getInstance(),
	})
	.onStart(async () => {
		console.log("🗄️  Initializing database connection...");

		try {
			await DatabaseConnection.connect();

			// Perform health check
			const isHealthy = await DatabaseConnection.healthCheck();
			if (!isHealthy) {
				console.warn(
					"⚠️  Database health check failed during startup, but continuing...",
				);
			} else {
				console.log("✅ Database ready and healthy");
			}
		} catch (error) {
			console.warn(
				"⚠️  Database connection failed during startup, but continuing in development mode...",
			);
			console.warn(
				`   Database error: ${error instanceof Error ? error.message : "Unknown error"}`,
			);
			console.warn(
				"   Please ensure your DATABASE_URL is correct and the database is running",
			);
		}
	})
	.onStop(async () => {
		console.log("🔌 Closing database connection...");
		try {
			await DatabaseConnection.disconnect();
		} catch (error) {
			console.warn("Warning: Error during database disconnect:", error);
		}
	})
	.as("global");
