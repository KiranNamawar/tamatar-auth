import { jwt } from "@elysiajs/jwt";
import { Elysia } from "elysia";
import { config } from "../config";

export interface JWTPayload {
	sub: string; // User ID
	email: string;
	username?: string;
	sessionId: string;
	iat?: number;
	exp?: number;
	iss?: string;
	aud?: string;
}

export interface RefreshTokenPayload {
	sub: string; // User ID
	sessionId: string;
	type: "refresh";
	iat?: number;
	exp?: number;
	iss?: string;
	aud?: string;
}

/**
 * JWT Plugin for Elysia with dual token support (access + refresh)
 */
export const jwtPlugin = new Elysia({ name: "jwt-auth" })
	.use(
		jwt({
			name: "jwt",
			secret: config.get().jwt.secret,
			exp: config.get().jwt.accessTokenExpiry,
			iss: config.get().jwt.issuer,
			aud: config.get().jwt.audience,
		}),
	)
	.use(
		jwt({
			name: "refreshJWT",
			secret: config.get().jwt.secret,
			exp: config.get().jwt.refreshTokenExpiry,
			iss: config.get().jwt.issuer,
			aud: config.get().jwt.audience,
		}),
	)
	.derive(({ jwt, refreshJWT }) => ({
		// Enhanced JWT utilities
		auth: {
			/**
			 * Generate both access and refresh tokens
			 */
			async signTokens(
				payload: Omit<JWTPayload, "iat" | "exp" | "iss" | "aud" | "type">,
			): Promise<{
				accessToken: string;
				refreshToken: string;
				expiresIn: number;
			}> {
				const accessToken = await jwt.sign(payload);
				const refreshToken = await refreshJWT.sign({
					sub: payload.sub,
					sessionId: payload.sessionId,
					type: "refresh",
				});

				// Parse expiry time from config (e.g., '15m' -> 900 seconds)
				const expiresIn = this.parseExpiryTime(
					config.get().jwt.accessTokenExpiry,
				);

				return {
					accessToken,
					refreshToken,
					expiresIn,
				};
			},

			/**
			 * Verify access token
			 */
			async verifyAccess(token: string): Promise<JWTPayload | false> {
				try {
					const payload = await jwt.verify(token);
					return payload as unknown as JWTPayload;
				} catch {
					return false;
				}
			},

			/**
			 * Verify refresh token
			 */
			async verifyRefresh(token: string): Promise<RefreshTokenPayload | false> {
				try {
					const payload = await refreshJWT.verify(token);
					if (
						payload &&
						typeof payload === "object" &&
						"type" in payload &&
						payload.type === "refresh"
					) {
						return payload as unknown as RefreshTokenPayload;
					}
					return false;
				} catch {
					return false;
				}
			},

			/**
			 * Parse expiry time string to seconds
			 */
			parseExpiryTime(expiry: string): number {
				const units: Record<string, number> = {
					s: 1,
					m: 60,
					h: 3600,
					d: 86400,
					w: 604800,
				};

				const match = expiry.match(/^(\d+)([smhdw])$/);
				if (!match) return 900; // Default 15 minutes

				const [, amount, unit] = match;
				return parseInt(amount, 10) * (units[unit] || 1);
			},
		},
	}))
	.as("scoped");

/**
 * Standalone JWT utilities (when not using the plugin)
 */
export class JWTSecurity {
	private static getConfig() {
		return config.get().jwt;
	}

	/**
	 * Create a temporary JWT instance for standalone usage
	 */
	private static createJWTInstance() {
		const cfg = JWTSecurity.getConfig();
		return jwt({
			secret: cfg.secret,
			exp: cfg.accessTokenExpiry,
			iss: cfg.issuer,
			aud: cfg.audience,
		});
	}

	/**
	 * Generate an access token (standalone)
	 */
	static async generateAccessToken(
		payload: Omit<JWTPayload, "iat" | "exp" | "iss" | "aud">,
	): Promise<string> {
		const jwtInstance = JWTSecurity.createJWTInstance();
		// Create a temporary Elysia instance to use the JWT plugin
		const tempApp = new Elysia().use(jwtInstance);
		const context = await tempApp.compile();

		// Access the jwt function from the context
		return await (context as any).jwt.sign(payload);
	}

	/**
	 * Generate a refresh token (standalone)
	 */
	static async generateRefreshToken(
		userId: string,
		sessionId: string,
	): Promise<string> {
		const cfg = JWTSecurity.getConfig();
		const refreshJWTInstance = jwt({
			secret: cfg.secret,
			exp: cfg.refreshTokenExpiry,
			iss: cfg.issuer,
			aud: cfg.audience,
		});

		const tempApp = new Elysia().use(refreshJWTInstance);
		const context = await tempApp.compile();

		return await (context as any).jwt.sign({
			sub: userId,
			sessionId,
			type: "refresh",
		});
	}

	/**
	 * Verify and decode a token (standalone)
	 */
	static async verifyToken(token: string): Promise<JWTPayload | null> {
		try {
			const jwtInstance = JWTSecurity.createJWTInstance();
			const tempApp = new Elysia().use(jwtInstance);
			const context = await tempApp.compile();

			const payload = await (context as any).jwt.verify(token);
			return payload ? (payload as JWTPayload) : null;
		} catch {
			return null;
		}
	}

	/**
	 * Check if token is expired (decode without verification)
	 */
	static isTokenExpired(token: string): boolean {
		try {
			const parts = token.split(".");
			if (parts.length !== 3) return true;

			const payload = JSON.parse(atob(parts[1]));
			if (!payload.exp) return true;

			return Date.now() >= payload.exp * 1000;
		} catch {
			return true;
		}
	}

	/**
	 * Get token expiration time
	 */
	static getTokenExpiration(token: string): Date | null {
		try {
			const parts = token.split(".");
			if (parts.length !== 3) return null;

			const payload = JSON.parse(atob(parts[1]));
			if (!payload.exp) return null;

			return new Date(payload.exp * 1000);
		} catch {
			return null;
		}
	}
}
