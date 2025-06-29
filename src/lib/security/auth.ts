import { bearer } from "@elysiajs/bearer";
import { Elysia } from "elysia";
import type { JWTPayload } from "./jwt";
import { jwtPlugin } from "./jwt";

export interface AuthenticatedContext {
	user: JWTPayload;
	userId: string;
}

/**
 * Authentication middleware plugin using Bearer token and JWT
 */
export const authMiddleware = new Elysia({ name: "auth-middleware" })
	.use(bearer())
	.use(jwtPlugin)
	.derive(({ bearer, auth }) => ({
		user: null as JWTPayload | null,
		userId: null as string | null,
	}))
	.resolve(async ({ bearer, auth }) => {
		if (!bearer) {
			return { user: null, userId: null };
		}

		try {
			const payload = await auth.verifyAccess(bearer);
			if (payload !== false) {
				return {
					user: payload,
					userId: payload.sub,
				};
			}
			return { user: null, userId: null };
		} catch {
			return { user: null, userId: null };
		}
	})
	.macro({
		/**
		 * Require authentication for this route
		 */
		requireAuth(enabled: boolean = true) {
			if (!enabled) return;

			return {
				beforeHandle({ user, error, set }: any) {
					if (!user) {
						set.headers["WWW-Authenticate"] = 'Bearer realm="api"';
						return error(401, {
							error: "Authentication required",
							code: "MISSING_AUTH",
							message: "Please provide a valid Bearer token",
						});
					}
				},
			};
		},

		/**
		 * Require admin access
		 */
		requireAdmin(enabled: boolean = true) {
			if (!enabled) return;

			return {
				beforeHandle({ user, error }: any) {
					if (!user) {
						return error(401, {
							error: "Authentication required",
							code: "MISSING_AUTH",
						});
					}

					// Check if user is admin (you'll need to implement this based on your user model)
					const isAdmin = (user as any).isAdmin || false;
					if (!isAdmin) {
						return error(403, {
							error: "Admin access required",
							code: "ADMIN_REQUIRED",
						});
					}
				},
			};
		},

		/**
		 * Require specific role for this route
		 */
		requireRole(role: string) {
			return {
				beforeHandle({ user, error }: any) {
					if (!user) {
						return error(401, {
							error: "Authentication required",
							code: "MISSING_AUTH",
						});
					}

					// Note: You'll need to add roles to your user model and JWT payload
					// For now, this is a placeholder
					const userRoles = (user as any).roles || [];
					if (!userRoles.includes(role)) {
						return error(403, {
							error: `Role required: ${role}`,
							code: "INSUFFICIENT_ROLE",
						});
					}
				},
			};
		},
	})
	.as("scoped");

/**
 * Simple authentication guard functions (alternative to macros)
 */
export const authGuard = {
	/**
	 * Require authentication for this route
	 */
	requireAuth: ({ user, error, set }: any) => {
		if (!user) {
			set.headers["WWW-Authenticate"] = 'Bearer realm="api"';
			return error(401, {
				error: "Authentication required",
				code: "MISSING_AUTH",
				message: "Please provide a valid Bearer token",
			});
		}
	},

	/**
	 * Require admin access
	 */
	requireAdmin: ({ user, error }: any) => {
		if (!user) {
			return error(401, {
				error: "Authentication required",
				code: "MISSING_AUTH",
			});
		}

		// Check if user is admin (you'll need to implement this based on your user model)
		const isAdmin = (user as any).isAdmin || false;
		if (!isAdmin) {
			return error(403, {
				error: "Admin access required",
				code: "ADMIN_REQUIRED",
			});
		}
	},

	/**
	 * Require specific role for this route
	 */
	requireRole:
		(role: string) =>
		({ user, error }: any) => {
			if (!user) {
				return error(401, {
					error: "Authentication required",
					code: "MISSING_AUTH",
				});
			}

			// Note: You'll need to add roles to your user model and JWT payload
			// For now, this is a placeholder
			const userRoles = (user as any).roles || [];
			if (!userRoles.includes(role)) {
				return error(403, {
					error: `Role required: ${role}`,
					code: "INSUFFICIENT_ROLE",
				});
			}
		},
};

/**
 * Combined authentication plugin
 */
export const authPlugin = new Elysia({ name: "auth-plugin" })
	.use(authMiddleware)
	.as("global");
