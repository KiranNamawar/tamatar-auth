import { t } from "elysia";

// User-related schemas
export const UserSchema = t.Object({
	id: t.String({ description: "Unique user identifier" }),
	email: t.String({ format: "email", description: "User email address" }),
	username: t.String({ description: "Unique username" }),
	firstName: t.String({ description: "User's first name" }),
	lastName: t.Union([t.String(), t.Null()], { description: "User's last name" }),
	avatar: t.Union([t.String(), t.Null()], { description: "User avatar URL" }),
	emailVerified: t.Boolean({ description: "Whether the user's email is verified" }),
	createdAt: t.String({ format: "date-time", description: "Account creation timestamp" }),
	updatedAt: t.String({ format: "date-time", description: "Last update timestamp" }),
});

export const SessionSchema = t.Object({
	id: t.String({ description: "Session identifier" }),
	userId: t.String({ description: "User identifier" }),
	userAgent: t.Union([t.String(), t.Null()], { description: "Browser user agent" }),
	ipAddress: t.Union([t.String(), t.Null()], { description: "IP address" }),
	isValid: t.Boolean({ description: "Whether the session is valid" }),
	expiresAt: t.String({ format: "date-time", description: "Session expiration timestamp" }),
	createdAt: t.String({ format: "date-time", description: "Session creation timestamp" }),
});

export const TokensSchema = t.Object({
	accessToken: t.String({ description: "JWT access token (15 minutes)" }),
	refreshToken: t.String({ description: "JWT refresh token (7 days)" }),
	expiresIn: t.Number({ description: "Access token expiry in seconds" }),
});

// Request schemas
export const RegisterRequestSchema = t.Object({
	email: t.String({ 
		format: "email", 
		description: "User email address",
		examples: ["user@example.com"]
	}),
	password: t.String({
		minLength: 8,
		description: "Password (minimum 8 characters with uppercase, lowercase, number, and special character)",
		examples: ["SecurePass123!"]
	}),
	firstName: t.String({
		minLength: 1,
		maxLength: 50,
		description: "First name",
		examples: ["John"]
	}),
	lastName: t.Optional(t.String({
		maxLength: 50,
		description: "Last name (optional)",
		examples: ["Doe"]
	})),
	username: t.String({
		minLength: 3,
		maxLength: 30,
		pattern: "^[a-zA-Z0-9_]+$",
		description: "Unique username (3-30 characters, alphanumeric and underscore only)",
		examples: ["johndoe123"]
	}),
});

export const LoginRequestSchema = t.Object({
	email: t.String({ 
		format: "email", 
		description: "User email address",
		examples: ["user@example.com"]
	}),
	password: t.String({ 
		description: "User password",
		examples: ["SecurePass123!"]
	}),
});

export const EmailVerificationRequestSchema = t.Object({
	token: t.String({ 
		description: "Email verification token from the verification email",
		examples: ["abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"]
	}),
});

export const ResendVerificationRequestSchema = t.Object({
	email: t.String({ 
		format: "email", 
		description: "User email address to resend verification to",
		examples: ["user@example.com"]
	}),
});

export const ForgotPasswordRequestSchema = t.Object({
	email: t.String({ 
		format: "email", 
		description: "User email address to send password reset to",
		examples: ["user@example.com"]
	}),
});

export const ResetPasswordRequestSchema = t.Object({
	token: t.String({ 
		description: "Password reset token from the reset email",
		examples: ["abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"]
	}),
	newPassword: t.String({
		minLength: 8,
		description: "New password (minimum 8 characters with uppercase, lowercase, number, and special character)",
		examples: ["NewSecurePass123!"]
	}),
});

export const RefreshTokenRequestSchema = t.Object({
	refreshToken: t.String({ 
		description: "JWT refresh token obtained from login",
		examples: ["eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."]
	}),
});

// Response schemas
export const AuthSuccessResponseSchema = t.Object({
	success: t.Literal(true),
	data: t.Object({
		user: UserSchema,
		tokens: TokensSchema,
		session: SessionSchema,
	}),
});

export const RegisterSuccessResponseSchema = t.Object({
	success: t.Literal(true),
	data: t.Object({
		user: UserSchema,
	}),
	message: t.String({ description: "Success message" }),
});

export const UserProfileResponseSchema = t.Object({
	success: t.Literal(true),
	data: t.Object({
		user: UserSchema,
	}),
});

export const TokenRefreshResponseSchema = t.Object({
	success: t.Literal(true),
	data: t.Object({
		accessToken: t.String({ description: "New JWT access token" }),
		expiresIn: t.Number({ description: "Token expiry in seconds" }),
	}),
});

export const SuccessMessageResponseSchema = t.Object({
	success: t.Literal(true),
	message: t.String({ description: "Success message" }),
});

// Error response schemas
export const ErrorResponseSchema = t.Object({
	success: t.Literal(false),
	error: t.Object({
		message: t.String({ description: "Error message" }),
		code: t.String({ description: "Error code" }),
		details: t.Optional(t.Any({ description: "Additional error details" })),
	}),
});

export const ValidationErrorResponseSchema = t.Object({
	success: t.Literal(false),
	error: t.Object({
		message: t.String({ description: "Validation error message" }),
		code: t.Literal("VALIDATION_ERROR"),
		details: t.Array(t.Object({
			field: t.String({ description: "Field name that failed validation" }),
			message: t.String({ description: "Validation error message for the field" }),
			received: t.Any({ description: "Value that was received" }),
		})),
	}),
});

// Security schema for bearer auth
export const BearerAuthSchema = {
	BearerAuth: [],
};

// Common response examples
export const CommonResponses = {
	400: {
		description: "Bad Request - Invalid input data",
		content: {
			"application/json": {
				schema: ValidationErrorResponseSchema,
				examples: {
					validation: {
						summary: "Validation Error",
						value: {
							success: false,
							error: {
								message: "Request validation failed",
								code: "VALIDATION_ERROR",
								details: [
									{
										field: "email",
										message: "Must be a valid email address",
										received: "invalid-email"
									}
								]
							}
						}
					}
				}
			}
		}
	},
	401: {
		description: "Unauthorized - Invalid or missing authentication",
		content: {
			"application/json": {
				schema: ErrorResponseSchema,
				examples: {
					missingToken: {
						summary: "Missing Token",
						value: {
							success: false,
							error: {
								message: "Authentication required",
								code: "MISSING_AUTH"
							}
						}
					},
					invalidToken: {
						summary: "Invalid Token",
						value: {
							success: false,
							error: {
								message: "Invalid or expired token",
								code: "INVALID_TOKEN"
							}
						}
					},
					invalidCredentials: {
						summary: "Invalid Credentials",
						value: {
							success: false,
							error: {
								message: "Invalid email or password",
								code: "INVALID_CREDENTIALS"
							}
						}
					}
				}
			}
		}
	},
	409: {
		description: "Conflict - Resource already exists or business logic conflict",
		content: {
			"application/json": {
				schema: ErrorResponseSchema,
				examples: {
					userExists: {
						summary: "User Already Exists",
						value: {
							success: false,
							error: {
								message: "An account with this email already exists",
								code: "USER_ALREADY_EXISTS"
							}
						}
					},
					emailNotVerified: {
						summary: "Email Not Verified",
						value: {
							success: false,
							error: {
								message: "Please verify your email address to continue",
								code: "EMAIL_NOT_VERIFIED"
							}
						}
					}
				}
			}
		}
	},
	500: {
		description: "Internal Server Error",
		content: {
			"application/json": {
				schema: ErrorResponseSchema,
				examples: {
					serverError: {
						summary: "Server Error",
						value: {
							success: false,
							error: {
								message: "An unexpected error occurred",
								code: "INTERNAL_SERVER_ERROR"
							}
						}
					}
				}
			}
		}
	}
};
