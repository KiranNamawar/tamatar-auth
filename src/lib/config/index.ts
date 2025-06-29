import type { Config } from "./schema";
import { validateConfig } from "./schema";

class ConfigService {
	private config: Config;

	constructor() {
		this.config = this.loadConfig();
	}

	private loadConfig(): Config {
		const rawConfig = {
			nodeEnv: process.env.NODE_ENV as Config["nodeEnv"],
			port: process.env.PORT ? parseInt(process.env.PORT, 10) : undefined,
			host: process.env.HOST,

			database: {
				url: process.env.DATABASE_URL ?? "",
				// Constants - no longer configurable via env
				poolSize: 10,
				connectionTimeout: 5000,
				queryTimeout: 10000,
			},

			jwt: {
				secret: process.env.JWT_SECRET,
				// Constants - no longer configurable via env
				accessTokenExpiry: "15m",
				refreshTokenExpiry: "7d",
				issuer: "tamatar-auth",
				audience: "tamatar-services",
			},

			email: {
				resendApiKey: process.env.RESEND_API_KEY,
				fromEmail: process.env.FROM_EMAIL,
				replyToEmail: process.env.REPLY_TO_EMAIL,
				// Constants - no longer configurable via env
				verificationEnabled: true,
				passwordResetEnabled: true,
			},

			security: {
				corsOrigin:
					process.env.CORS_ORIGIN?.split(",") || process.env.CORS_ORIGIN,
				// Constants - no longer configurable via env
				corsCredentials: true,
				rateLimitEnabled: true,
				rateLimitWindow: "15m",
				rateLimitMax: 100,
			},

			urls: {
				frontendService: process.env.FRONTEND_SERVICE_URL,
				adminService: process.env.ADMIN_SERVICE_URL,
				authService: process.env.AUTH_SERVICE_URL,
			},

			monitoring: {
				logLevel: process.env.LOG_LEVEL as Config["monitoring"]["logLevel"],
				// Constant - no longer configurable via env
				logFormat: "json" as const,
				sentryDsn: process.env.SENTRY_DSN,
				sentryEnvironment: process.env.SENTRY_ENVIRONMENT,
			},

			features: {
				// Constants - no longer configurable via env
				registrationEnabled: true,
				oauthEnabled: true,
				passwordResetEnabled: true,
			},
		};

		try {
			return validateConfig(rawConfig);
		} catch (error) {
			console.error(
				"❌ Configuration validation failed:",
				error instanceof Error ? error.message : error,
			);
			process.exit(1);
		}
	}

	get(): Config {
		return this.config;
	}

	isDevelopment(): boolean {
		return this.config.nodeEnv === "development";
	}

	isProduction(): boolean {
		return this.config.nodeEnv === "production";
	}

	isTest(): boolean {
		return this.config.nodeEnv === "test";
	}

	logSafeConfiguration(): void {
		// Log safe configuration (without secrets)
		const safeConfig = {
			nodeEnv: this.config.nodeEnv,
			port: this.config.port,
			host: this.config.host,
			features: this.config.features,
			database: {
				poolSize: this.config.database.poolSize,
				connectionTimeout: this.config.database.connectionTimeout,
				// Only show host part of database URL
				host:
					this.config.database.url.split("@")[1]?.split("/")[0] || "unknown",
			},
			jwt: {
				issuer: this.config.jwt.issuer,
				audience: this.config.jwt.audience,
				accessTokenExpiry: this.config.jwt.accessTokenExpiry,
				refreshTokenExpiry: this.config.jwt.refreshTokenExpiry,
			},
			email: {
				verificationEnabled: this.config.email.verificationEnabled,
				passwordResetEnabled: this.config.email.passwordResetEnabled,
				fromEmail: this.config.email.fromEmail,
			},
			security: {
				rateLimitEnabled: this.config.security.rateLimitEnabled,
				corsCredentials: this.config.security.corsCredentials,
				rateLimitWindow: this.config.security.rateLimitWindow,
				rateLimitMax: this.config.security.rateLimitMax,
			},
			monitoring: {
				logLevel: this.config.monitoring.logLevel,
				logFormat: this.config.monitoring.logFormat,
				sentryEnabled: !!this.config.monitoring.sentryDsn,
			},
		};

		console.log(
			"📋 Application configuration:",
			JSON.stringify(safeConfig, null, 2),
		);
	}
}

export const config = new ConfigService();
