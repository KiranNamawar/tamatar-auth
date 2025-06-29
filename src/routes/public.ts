import { Elysia, t } from "elysia";
import { authService } from "../lib/security/service";

/**
 * Public authentication routes (no authentication required)
 * Routes: /register, /login, /verify-email, /resend-verification, /forgot-password, /reset-password, /refresh
 */
export const publicRoutes = new Elysia({ name: "public-routes" })
	.use(authService)

	// User Registration
	.post(
		"/register",
		async ({ body, authService, set }) => {
			try {
				const result = await authService.register(body);
				set.status = 201;
				return {
					success: true,
					data: result,
					message: "Registration successful. Please verify your email address.",
				};
			} catch (error) {
				set.status = 400;
				return {
					success: false,
					error: {
						message: error instanceof Error ? error.message : "Registration failed",
						code: "REGISTRATION_FAILED",
					},
				};
			}
		},
		{
			body: t.Object({
				email: t.String({ format: "email" }),
				username: t.String({ minLength: 3, maxLength: 30 }),
				firstName: t.String({ minLength: 1, maxLength: 50 }),
				lastName: t.Optional(t.String({ maxLength: 50 })),
				password: t.String({ minLength: 8 }),
			}),
			detail: {
				tags: ["Authentication"],
				summary: "Register new user",
				description: "Create a new user account. An email verification will be sent to the provided email address.",
				responses: {
					201: {
						description: "Registration successful",
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
														emailVerified: { type: "boolean", example: false },
														createdAt: { type: "string", format: "date-time" },
														updatedAt: { type: "string", format: "date-time" }
													}
												}
											}
										},
										message: { type: "string", example: "Registration successful. Please verify your email address." }
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
												message: { type: "string", example: "Registration failed" },
												code: { type: "string", example: "REGISTRATION_FAILED" }
											}
										}
									}
								}
							}
						}
					},
					409: {
						description: "Conflict - User already exists",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "An account with this email already exists" },
												code: { type: "string", example: "USER_ALREADY_EXISTS" }
											}
										}
									}
								}
							}
						}
					}
				}
			},
		},
	)

	// User Login
	.post(
		"/login",
		async ({ body, headers, set, authService }) => {
			try {
				const loginData = {
					...body,
					userAgent: headers["user-agent"],
					ipAddress: headers["x-forwarded-for"] || headers["x-real-ip"],
				};

				const result = await authService.login(loginData);
				set.status = 200;
				return {
					success: true,
					data: result,
					message: "Login successful",
				};
			} catch (error) {
				set.status = 401;
				return {
					success: false,
					error: {
						message: error instanceof Error ? error.message : "Login failed",
						code: "LOGIN_FAILED",
					},
				};
			}
		},
		{
			body: t.Object({
				email: t.String({ format: "email" }),
				password: t.String(),
			}),
			detail: {
				tags: ["Authentication"],
				summary: "User login",
				description: "Authenticate user with email and password. Returns access token and user information.",
				responses: {
					200: {
						description: "Login successful",
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
														emailVerified: { type: "boolean", example: true }
													}
												},
												tokens: {
													type: "object",
													properties: {
														accessToken: { type: "string", example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." },
														refreshToken: { type: "string", example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." },
														expiresIn: { type: "number", example: 900 }
													}
												},
												session: {
													type: "object",
													properties: {
														id: { type: "string", example: "session_123abc" },
														expiresAt: { type: "string", format: "date-time" }
													}
												}
											}
										},
										message: { type: "string", example: "Login successful" }
									}
								}
							}
						}
					},
					401: {
						description: "Unauthorized - Invalid credentials",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Invalid email or password" },
												code: { type: "string", example: "INVALID_CREDENTIALS" }
											}
										}
									}
								}
							}
						}
					}
				}
			},
		},
	)

	// Refresh Token
	.post(
		"/refresh",
		async ({ body, authService, set }) => {
			try {
				const result = await authService.refreshToken({ refreshToken: body.refreshToken });
				set.status = 200;
				return {
					success: true,
					data: result,
					message: "Token refreshed successfully",
				};
			} catch (error) {
				set.status = 401;
				return {
					success: false,
					error: {
						message: error instanceof Error ? error.message : "Token refresh failed",
						code: "REFRESH_FAILED",
					},
				};
			}
		},
		{
			body: t.Object({
				refreshToken: t.String(),
			}),
			detail: {
				tags: ["Authentication"],
				summary: "Refresh access token",
				description: "Get a new access token using a valid refresh token.",
				responses: {
					200: {
						description: "Token refreshed successfully",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: true },
										data: {
											type: "object",
											properties: {
												tokens: {
													type: "object",
													properties: {
														accessToken: { type: "string", example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." },
														refreshToken: { type: "string", example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." },
														expiresIn: { type: "number", example: 900 }
													}
												}
											}
										},
										message: { type: "string", example: "Token refreshed successfully" }
									}
								}
							}
						}
					},
					401: {
						description: "Unauthorized - Invalid refresh token",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Invalid or expired refresh token" },
												code: { type: "string", example: "INVALID_REFRESH_TOKEN" }
											}
										}
									}
								}
							}
						}
					}
				}
			},
		},
	);
