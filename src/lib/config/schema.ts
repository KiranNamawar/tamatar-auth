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
		frontend: string;
		admin?: string;
		auth: string;
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

	if (!config.urls?.frontend) {
		errors.push("FRONTEND_URL is required");
	}

	if (!config.urls?.auth) {
		errors.push("AUTH_URL is required");
	}

	// Production-specific validations
	if (config.nodeEnv === "production") {
		if (
			config.jwt?.secret === "development-secret" ||
			config.jwt?.secret === "secret"
		) {
			errors.push("Development JWT secret cannot be used in production");
		}

		if (config.security?.rateLimitEnabled === false) {
			errors.push("Rate limiting must be enabled in production");
		}
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
			poolSize:
				typeof config.database?.poolSize === "number"
					? config.database.poolSize
					: 10,
			connectionTimeout:
				typeof config.database?.connectionTimeout === "number"
					? config.database.connectionTimeout
					: 5000,
			queryTimeout:
				typeof config.database?.queryTimeout === "number"
					? config.database.queryTimeout
					: 10000,
		},

		jwt: {
			secret: config.jwt.secret,
			accessTokenExpiry: config.jwt?.accessTokenExpiry || "15m",
			refreshTokenExpiry: config.jwt?.refreshTokenExpiry || "7d",
			issuer: config.jwt?.issuer || "tamatar-auth",
			audience: config.jwt?.audience || "tamatar-services",
		},

		email: {
			resendApiKey: config.email.resendApiKey,
			fromEmail: config.email?.fromEmail || "Tamatar Auth <auth@tamatar.dev>",
			replyToEmail: config.email?.replyToEmail,
			verificationEnabled: config.email?.verificationEnabled !== false,
			passwordResetEnabled: config.email?.passwordResetEnabled !== false,
		},

		security: {
			corsOrigin: config.security?.corsOrigin || "*",
			corsCredentials: config.security?.corsCredentials !== false,
			rateLimitEnabled: config.security?.rateLimitEnabled !== false,
			rateLimitWindow: config.security?.rateLimitWindow || "15m",
			rateLimitMax:
				typeof config.security?.rateLimitMax === "number"
					? config.security.rateLimitMax
					: 100,
		},

		urls: {
			frontend: config.urls.frontend,
			admin: config.urls?.admin,
			auth: config.urls.auth,
		},

		monitoring: {
			logLevel:
				(config.monitoring?.logLevel as Config["monitoring"]["logLevel"]) ||
				"info",
			logFormat:
				(config.monitoring?.logFormat as Config["monitoring"]["logFormat"]) ||
				"json",
			sentryDsn: config.monitoring?.sentryDsn,
			sentryEnvironment: config.monitoring?.sentryEnvironment,
		},

		features: {
			registrationEnabled: config.features?.registrationEnabled !== false,
			oauthEnabled: config.features?.oauthEnabled !== false,
			passwordResetEnabled: config.features?.passwordResetEnabled !== false,
		},
	};

	return validatedConfig;
}
