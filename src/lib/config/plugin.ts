import { Elysia } from "elysia";
import { config } from "./index";

export const configPlugin = new Elysia({ name: "config" })
	.decorate({
		config: config.get(),
	})
	.onStart(() => {
		console.log("🚀 Validating application configuration...");
		config.logSafeConfiguration();
		console.log("✅ Configuration validated successfully");
	})
	.as("global");
