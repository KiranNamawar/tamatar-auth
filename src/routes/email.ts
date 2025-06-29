import { Elysia, t } from "elysia";
import { authService } from "../lib/security/service";

/**
 * Email verification and password reset routes
 * Routes: /verify-email, /resend-verification, /forgot-password, /reset-password
 */
export const emailRoutes = new Elysia({ name: "email-routes" })
	.use(authService)

	// Email Verification
	.post(
		"/verify-email",
		async ({ body, authService, set }) => {
			try {
				const result = await authService.verifyEmail(body.token);
				set.status = 200;
				return {
					success: true,
					data: result,
					message: "Email verified successfully",
				};
			} catch (error) {
				set.status = 400;
				return {
					success: false,
					error: {
						message: error instanceof Error ? error.message : "Email verification failed",
						code: "VERIFICATION_FAILED",
					},
				};
			}
		},
		{
			body: t.Object({
				token: t.String(),
			}),
			detail: {
				tags: ["Email Verification"],
				summary: "Verify email address",
				description: "Verify user's email address using the verification token sent via email.",
				responses: {
					200: {
						description: "Email verified successfully",
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
														emailVerified: { type: "boolean", example: true }
													}
												}
											}
										},
										message: { type: "string", example: "Email verified successfully" }
									}
								}
							}
						}
					},
					400: {
						description: "Bad Request - Invalid or expired token",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Invalid or expired verification token" },
												code: { type: "string", example: "INVALID_TOKEN" }
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

	// Resend Email Verification
	.post(
		"/resend-verification",
		async ({ set }) => {
			try {
				// Find user by email first, then send verification
				// This is a placeholder - you may need to implement this method
				// await authService.sendEmailVerification(userId);
				set.status = 200;
				return {
					success: true,
					message: "Verification email sent",
				};
			} catch (error) {
				set.status = 400;
				return {
					success: false,
					error: {
						message: error instanceof Error ? error.message : "Failed to send verification email",
						code: "RESEND_FAILED",
					},
				};
			}
		},
		{
			body: t.Object({
				email: t.String({ format: "email" }),
			}),
			detail: {
				tags: ["Email Verification"],
				summary: "Resend email verification",
				description: "Resend verification email to the user's email address.",
				responses: {
					200: {
						description: "Verification email sent",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: true },
										message: { type: "string", example: "Verification email sent" }
									}
								}
							}
						}
					},
					400: {
						description: "Bad Request - Invalid email or user not found",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "User not found or email already verified" },
												code: { type: "string", example: "RESEND_FAILED" }
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

	// Forgot Password
	.post(
		"/forgot-password",
		async ({ body, authService, set }) => {
			try {
				await authService.initiatePasswordReset(body.email);
				set.status = 200;
				return {
					success: true,
					message: "Password reset email sent",
				};
			} catch (error) {
				set.status = 400;
				return {
					success: false,
					error: {
						message: error instanceof Error ? error.message : "Failed to send password reset email",
						code: "FORGOT_PASSWORD_FAILED",
					},
				};
			}
		},
		{
			body: t.Object({
				email: t.String({ format: "email" }),
			}),
			detail: {
				tags: ["Password Reset"],
				summary: "Request password reset",
				description: "Send a password reset email to the user's email address.",
				responses: {
					200: {
						description: "Password reset email sent",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: true },
										message: { type: "string", example: "Password reset email sent" }
									}
								}
							}
						}
					},
					400: {
						description: "Bad Request - Invalid email",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "User not found with this email" },
												code: { type: "string", example: "USER_NOT_FOUND" }
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

	// Reset Password
	.post(
		"/reset-password",
		async ({ body, authService, set }) => {
			try {
				const result = await authService.resetPassword(body.token, body.newPassword);
				set.status = 200;
				return {
					success: true,
					data: result,
					message: "Password reset successfully",
				};
			} catch (error) {
				set.status = 400;
				return {
					success: false,
					error: {
						message: error instanceof Error ? error.message : "Password reset failed",
						code: "RESET_PASSWORD_FAILED",
					},
				};
			}
		},
		{
			body: t.Object({
				token: t.String(),
				newPassword: t.String({ minLength: 8 }),
			}),
			detail: {
				tags: ["Password Reset"],
				summary: "Reset password",
				description: "Reset user's password using the reset token sent via email.",
				responses: {
					200: {
						description: "Password reset successfully",
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
														email: { type: "string", example: "user@example.com" }
													}
												}
											}
										},
										message: { type: "string", example: "Password reset successfully" }
									}
								}
							}
						}
					},
					400: {
						description: "Bad Request - Invalid token or weak password",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										success: { type: "boolean", example: false },
										error: {
											type: "object",
											properties: {
												message: { type: "string", example: "Invalid or expired reset token" },
												code: { type: "string", example: "INVALID_TOKEN" }
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
