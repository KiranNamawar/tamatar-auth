import { Elysia, t } from "elysia";
import { authMiddleware } from "../lib/security/auth";
import { authService } from "../lib/security/service";

/**
 * Protected user routes (require Bearer token authentication)
 * Routes: /me (GET, PATCH), /logout, /logout-all
 */
export const userRoutes = new Elysia({ name: "user-routes" })
	.use(authService)
	.use(authMiddleware)

	// Get Current User Profile
	.get(
		"/me",
		async ({ user, set }) => {
			if (!user) {
				set.status = 401;
				return {
					success: false,
					error: {
						message: "Authentication required",
						code: "MISSING_AUTH",
					},
				};
			}

			set.status = 200;
			return {
				success: true,
				data: { user },
				message: "User profile retrieved successfully",
			};
		},
		{
			detail: {
				tags: ["User Profile"],
				summary: "Get current user profile",
				description: "Retrieve the current authenticated user's profile information. Requires valid Bearer token.",
				responses: {
					200: {
						description: "User profile retrieved successfully",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: true },
										data: {
											type: "object",
											properties: {
												user: {
													type: "object",
													properties: {
														id: { type: "string", example: "clx123abc456def789" },
														email: { type: "string", example: "user@example.com" },
														username: { type: "string", example: "johndoe123" },
														firstName: { type: "string", example: "John" },
														lastName: { type: "string", nullable: true, example: "Doe" },
														avatar: { type: "string", nullable: true, example: null },
														emailVerified: { type: "boolean", example: true },
														createdAt: { type: "string", format: "date-time" },
														updatedAt: { type: "string", format: "date-time" }
													}
												}
											}
										},
										message: { type: "string", example: "User profile retrieved successfully" }
									}
								}
							}
						}
					},
					401: {
						description: "Unauthorized - Missing or invalid Bearer token",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Authentication required" },
												code: { type: "string", example: "MISSING_AUTH" }
											}
										}
									}
								}
							}
						}
					}
				},
				security: [{ BearerAuth: [] }]
			},
		},
	)

	// Update User Profile
	.patch(
		"/me",
		async ({ user, body, authService, set }) => {
			if (!user?.sub) {
				set.status = 401;
				return {
					success: false,
					error: {
						message: "Authentication required",
						code: "MISSING_AUTH",
					},
				};
			}

			try {
				const result = await authService.updateProfile(user.sub, body);
				set.status = 200;
				return {
					success: true,
					data: result,
					message: "Profile updated successfully",
				};
			} catch (error) {
				set.status = 400;
				return {
					success: false,
					error: {
						message: error instanceof Error ? error.message : "Profile update failed",
						code: "UPDATE_FAILED",
					},
				};
			}
		},
		{
			body: t.Object({
				firstName: t.Optional(t.String({ minLength: 1, maxLength: 50 })),
				lastName: t.Optional(t.String({ maxLength: 50 })),
				avatar: t.Optional(t.String({ format: "uri" })),
			}),
			detail: {
				tags: ["User Profile"],
				summary: "Update user profile",
				description: "Update the current authenticated user's profile information. Requires valid Bearer token.",
				responses: {
					200: {
						description: "Profile updated successfully",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: true },
										data: {
											type: "object",
											properties: {
												user: {
													type: "object",
													properties: {
														id: { type: "string", example: "clx123abc456def789" },
														email: { type: "string", example: "user@example.com" },
														username: { type: "string", example: "johndoe123" },
														firstName: { type: "string", example: "Jane" },
														lastName: { type: "string", nullable: true, example: "Smith" },
														avatar: { type: "string", nullable: true, example: "https://example.com/avatar.jpg" },
														emailVerified: { type: "boolean", example: true },
														updatedAt: { type: "string", format: "date-time" }
													}
												}
											}
										},
										message: { type: "string", example: "Profile updated successfully" }
									}
								}
							}
						}
					},
					400: {
						description: "Bad Request - Invalid input data",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Profile update failed" },
												code: { type: "string", example: "UPDATE_FAILED" }
											}
										}
									}
								}
							}
						}
					},
					401: {
						description: "Unauthorized - Missing or invalid Bearer token",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Authentication required" },
												code: { type: "string", example: "MISSING_AUTH" }
											}
										}
									}
								}
							}
						}
					}
				},
				security: [{ BearerAuth: [] }]
			},
		},
	)

	// Logout Current Session
	.post(
		"/logout",
		async ({ user, authService, set }) => {
			if (!user?.sessionId) {
				set.status = 401;
				return {
					success: false,
					error: {
						message: "Authentication required",
						code: "MISSING_AUTH",
					},
				};
			}

			try {
				await authService.logout(user.sessionId);
				set.status = 200;
				return {
					success: true,
					message: "Logout successful",
				};
			} catch {
				set.status = 500;
				return {
					success: false,
					error: {
						message: "Logout failed",
						code: "LOGOUT_FAILED",
					},
				};
			}
		},
		{
			detail: {
				tags: ["Session Management"],
				summary: "Logout current session",
				description: "Logout the current user session and invalidate the Bearer token.",
				responses: {
					200: {
						description: "Logout successful",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: true },
										message: { type: "string", example: "Logout successful" }
									}
								}
							}
						}
					},
					401: {
						description: "Unauthorized - Missing or invalid Bearer token",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Authentication required" },
												code: { type: "string", example: "MISSING_AUTH" }
											}
										}
									}
								}
							}
						}
					},
					500: {
						description: "Internal Server Error - Logout failed",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Logout failed" },
												code: { type: "string", example: "LOGOUT_FAILED" }
											}
										}
									}
								}
							}
						}
					}
				},
				security: [{ BearerAuth: [] }]
			},
		},
	)

	// Logout All Sessions
	.post(
		"/logout-all",
		async ({ user, authService, set }) => {
			if (!user?.sub) {
				set.status = 401;
				return {
					success: false,
					error: {
						message: "Authentication required",
						code: "MISSING_AUTH",
					},
				};
			}

			try {
				await authService.logoutAll(user.sub);
				set.status = 200;
				return {
					success: true,
					message: "Logged out from all devices",
				};
			} catch {
				set.status = 500;
				return {
					success: false,
					error: {
						message: "Logout failed",
						code: "LOGOUT_ALL_FAILED",
					},
				};
			}
		},
		{
			detail: {
				tags: ["Session Management"],
				summary: "Logout all sessions",
				description: "Logout from all user sessions across all devices. Requires valid Bearer token.",
				responses: {
					200: {
						description: "Logged out from all devices",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: true },
										message: { type: "string", example: "Logged out from all devices" }
									}
								}
							}
						}
					},
					401: {
						description: "Unauthorized - Missing or invalid Bearer token",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Authentication required" },
												code: { type: "string", example: "MISSING_AUTH" }
											}
										}
									}
								}
							}
						}
					},
					500: {
						description: "Internal Server Error - Logout failed",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Logout failed" },
												code: { type: "string", example: "LOGOUT_ALL_FAILED" }
											}
										}
									}
								}
							}
						}
					}
				},
				security: [{ BearerAuth: [] }]
			},
		},
	);
