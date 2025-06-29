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
				poolSize: process.env.DATABASE_POOL_SIZE
					? parseInt(process.env.DATABASE_POOL_SIZE, 10)
					: undefined,
				connectionTimeout: process.env.DATABASE_CONNECTION_TIMEOUT
					? parseInt(process.env.DATABASE_CONNECTION_TIMEOUT, 10)
					: undefined,
				queryTimeout: process.env.DATABASE_QUERY_TIMEOUT
					? parseInt(process.env.DATABASE_QUERY_TIMEOUT, 10)
					: undefined,
			},

			jwt: {
				secret: process.env.JWT_SECRET,
				accessTokenExpiry: process.env.JWT_ACCESS_TOKEN_EXPIRY,
				refreshTokenExpiry: process.env.JWT_REFRESH_TOKEN_EXPIRY,
				issuer: process.env.JWT_ISSUER,
				audience: process.env.JWT_AUDIENCE,
			},

			email: {
				resendApiKey: process.env.RESEND_API_KEY,
				fromEmail: process.env.FROM_EMAIL,
				replyToEmail: process.env.REPLY_TO_EMAIL,
				verificationEnabled: process.env.EMAIL_VERIFICATION_ENABLED !== "false",
				passwordResetEnabled: process.env.PASSWORD_RESET_ENABLED !== "false",
			},

			security: {
				corsOrigin:
					process.env.CORS_ORIGIN?.split(",") || process.env.CORS_ORIGIN,
				corsCredentials: process.env.CORS_CREDENTIALS !== "false",
				rateLimitEnabled: process.env.RATE_LIMIT_ENABLED !== "false",
				rateLimitWindow: process.env.RATE_LIMIT_WINDOW,
				rateLimitMax: process.env.RATE_LIMIT_MAX_REQUESTS
					? parseInt(process.env.RATE_LIMIT_MAX_REQUESTS, 10)
					: undefined,
			},

			urls: {
				frontend: process.env.FRONTEND_URL,
				admin: process.env.ADMIN_URL,
				auth: process.env.AUTH_URL,
			},

			monitoring: {
				logLevel: process.env.LOG_LEVEL as Config["monitoring"]["logLevel"],
				logFormat: process.env.LOG_FORMAT as Config["monitoring"]["logFormat"],
				sentryDsn: process.env.SENTRY_DSN,
				sentryEnvironment: process.env.SENTRY_ENVIRONMENT,
			},

			features: {
				registrationEnabled:
					process.env.FEATURE_REGISTRATION_ENABLED !== "false",
				oauthEnabled: process.env.FEATURE_OAUTH_ENABLED !== "false",
				passwordResetEnabled:
					process.env.FEATURE_PASSWORD_RESET_ENABLED !== "false",
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
