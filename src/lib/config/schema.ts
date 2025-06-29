// For now, we'll use a simple approach without zod since it's not installed
// We can upgrade to zod later for better validation

export interface Config {
	// Environment
	nodeEnv: "development" | "test" | "production";
	port: number;
	host: string;

	// Database
	database: {
		url: string;
		poolSize: number;
		connectionTimeout: number;
		queryTimeout: number;
	};

	// JWT
	jwt: {
		secret: string;
		accessTokenExpiry: string;
		refreshTokenExpiry: string;
		issuer: string;
		audience: string;
	};

	// Email
	email: {
		resendApiKey: string;
		fromEmail: string;
		replyToEmail?: string;
		verificationEnabled: boolean;
		passwordResetEnabled: boolean;
	};

	// Security
	security: {
		corsOrigin: string | string[];
		corsCredentials: boolean;
		rateLimitEnabled: boolean;
		rateLimitWindow: string;
		rateLimitMax: number;
	};

	// URLs
	urls: {
		frontendService: string;
		adminService?: string;
		authService: string;
	};

	// Monitoring
	monitoring: {
		logLevel: "debug" | "info" | "warn" | "error";
		logFormat: "json" | "simple";
		sentryDsn?: string;
		sentryEnvironment?: string;
	};

	// Features
	features: {
		registrationEnabled: boolean;
		oauthEnabled: boolean;
		passwordResetEnabled: boolean;
	};
}

export function validateConfig(config: any): Config {
	const errors: string[] = [];

	// Required validations
	if (!config.database?.url) {
		errors.push("DATABASE_URL is required");
	}

	if (!config.jwt?.secret || config.jwt.secret.length < 32) {
		errors.push("JWT_SECRET is required and must be at least 32 characters");
	}

	if (!config.email?.resendApiKey) {
		errors.push("RESEND_API_KEY is required");
	}

	if (!config.urls?.frontendService) {
		errors.push("FRONTEND_SERVICE_URL is required");
	}

	if (!config.urls?.authService) {
		errors.push("AUTH_SERVICE_URL is required");
	}

	// Production-specific validations
	if (config.nodeEnv === "production") {
		if (
			config.jwt?.secret === "development-secret" ||
			config.jwt?.secret === "secret"
		) {
			errors.push("Development JWT secret cannot be used in production");
		}

		// Rate limiting is now always enabled (hardcoded), so no need to check
	}

	if (errors.length > 0) {
		throw new Error(`Configuration validation failed: ${errors.join(", ")}`);
	}

	// Ensure all fields have proper defaults
	const validatedConfig: Config = {
		nodeEnv: (config.nodeEnv as Config["nodeEnv"]) || "development",
		port: typeof config.port === "number" ? config.port : 3000,
		host: config.host || "0.0.0.0",

		database: {
			url: config.database.url,
			poolSize: config.database.poolSize, // Now hardcoded to 10
			connectionTimeout: config.database.connectionTimeout, // Now hardcoded to 5000
			queryTimeout: config.database.queryTimeout, // Now hardcoded to 10000
		},

		jwt: {
			secret: config.jwt.secret,
			accessTokenExpiry: config.jwt.accessTokenExpiry, // Now hardcoded to "15m"
			refreshTokenExpiry: config.jwt.refreshTokenExpiry, // Now hardcoded to "7d"
			issuer: config.jwt.issuer, // Now hardcoded to "tamatar-auth"
			audience: config.jwt.audience, // Now hardcoded to "tamatar-services"
		},

		email: {
			resendApiKey: config.email.resendApiKey,
			fromEmail: config.email?.fromEmail || "Tamatar Auth <auth@tamatar.dev>",
			replyToEmail: config.email?.replyToEmail,
			verificationEnabled: config.email.verificationEnabled, // Now hardcoded to true
			passwordResetEnabled: config.email.passwordResetEnabled, // Now hardcoded to true
		},

		security: {
			corsOrigin: config.security?.corsOrigin || "*", // Default to allow all for microservices
			corsCredentials: config.security.corsCredentials, // Now hardcoded to true
			rateLimitEnabled: config.security.rateLimitEnabled, // Now hardcoded to true
			rateLimitWindow: config.security.rateLimitWindow, // Now hardcoded to "15m"
			rateLimitMax: config.security.rateLimitMax, // Now hardcoded to 100
		},

		urls: {
			frontendService: config.urls.frontendService,
			adminService: config.urls?.adminService,
			authService: config.urls.authService,
		},

		monitoring: {
			logLevel:
				(config.monitoring?.logLevel as Config["monitoring"]["logLevel"]) ||
				"info",
			logFormat: config.monitoring.logFormat, // Now hardcoded to "json"
			sentryDsn: config.monitoring?.sentryDsn,
			sentryEnvironment: config.monitoring?.sentryEnvironment,
		},

		features: {
			registrationEnabled: config.features.registrationEnabled, // Now hardcoded to true
			oauthEnabled: config.features.oauthEnabled, // Now hardcoded to true
			passwordResetEnabled: config.features.passwordResetEnabled, // Now hardcoded to true
		},
	};

	return validatedConfig;
}
