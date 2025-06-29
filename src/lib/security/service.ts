import { Elysia } from "elysia";
import type { User } from "../db";
import { repositoryPlugin } from "../db/repositories";
import { emailService } from "../email/resend";
import { jwtPlugin } from "./jwt";
import { PasswordSecurity } from "./password";

export interface LoginRequest {
	email: string;
	password: string;
	userAgent?: string;
	ipAddress?: string;
}

export interface RegisterRequest {
	email: string;
	password: string;
	firstName: string;
	lastName?: string;
	username?: string;
}

export interface AuthResponse {
	user: Omit<User, "password">;
	tokens: {
		accessToken: string;
		refreshToken: string;
		expiresIn: number;
	};
	session: {
		id: string;
		expiresAt: Date;
	};
}

export interface RefreshRequest {
	refreshToken: string;
}

/**
 * Authentication Service Plugin
 * Provides user registration, login, logout, and token refresh functionality
 */
export const authService = new Elysia({ name: "auth-service" })
	.use(repositoryPlugin)
	.use(jwtPlugin)
	.use(emailService)
	.derive(({ userRepo, sessionRepo, emailVerificationTokenRepo, passwordResetTokenRepo, auth, emailService }) => ({
		authService: {
			/**
			 * Register a new user
			 */
			async register(data: RegisterRequest): Promise<AuthResponse> {
				// Validate password strength
				const passwordValidation = PasswordSecurity.validateStrength(
					data.password,
				);
				if (!passwordValidation.isValid) {
					throw new Error(
						`Password validation failed: ${passwordValidation.errors.join(", ")}`,
					);
				}

				// Check if user already exists
				const existingUser = await userRepo.findByEmail(data.email);
				if (existingUser) {
					throw new Error("User already exists with this email");
				}

				// Hash password
				const passwordHash = await PasswordSecurity.hash(data.password);

				// Create user
				const user = await userRepo.create({
					email: data.email.toLowerCase().trim(),
					password: passwordHash,
					firstName: data.firstName.trim(),
					lastName: data.lastName?.trim(),
					username: data.username?.toLowerCase().trim() || `user_${Date.now()}`, // Generate username if not provided
					emailVerified: false, // Requires email verification
				});

				// Create session
				const session = await sessionRepo.create({
					user: { connect: { id: user.id } },
					userAgent: "",
					ipAddress: "",
					expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
				});

				// Generate tokens
				const tokens = await auth.signTokens({
					sub: user.id,
					email: user.email,
					username: user.username,
					sessionId: session.id,
				});

				// Send email verification (if enabled)
				try {
					await this.sendEmailVerification(user.id);
				} catch (error) {
					// Don't fail registration if email sending fails
					console.warn("Failed to send verification email:", error);
				}

				// User already doesn't have password due to repository select fields
				return {
					user,
					tokens,
					session: {
						id: session.id,
						expiresAt: session.expiresAt,
					},
				};
			},

			/**
			 * Login an existing user
			 */
			async login(data: LoginRequest): Promise<AuthResponse> {
				// Find user with password
				const user = await userRepo.findByEmailWithPassword(
					data.email.toLowerCase().trim(),
				);
				if (!user) {
					throw new Error("Invalid credentials");
				}

				// Check if password exists (user must have a password to login)
				if (!user.password) {
					throw new Error("Invalid credentials");
				}

				// Verify password
				const isValidPassword = await PasswordSecurity.verify(
					data.password,
					user.password,
				);
				if (!isValidPassword) {
					throw new Error("Invalid credentials");
				}

				// Check if email is verified (optional, depends on your requirements)
				if (!user.emailVerified) {
					throw new Error("Email verification required");
				}

				// Create session
				const session = await sessionRepo.create({
					user: { connect: { id: user.id } },
					userAgent: data.userAgent || "",
					ipAddress: data.ipAddress || "",
					expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days
				});

				// Generate tokens
				const tokens = await auth.signTokens({
					sub: user.id,
					email: user.email,
					username: user.username,
					sessionId: session.id,
				});

				// Get user without password using safe method
				const safeUser = await userRepo.findById(user.id);
				if (!safeUser) {
					throw new Error("User not found");
				}

				return {
					user: safeUser,
					tokens,
					session: {
						id: session.id,
						expiresAt: session.expiresAt,
					},
				};
			},

			/**
			 * Refresh access token using refresh token
			 */
			async refreshToken(
				data: RefreshRequest,
			): Promise<Pick<AuthResponse, "tokens">> {
				// Verify refresh token
				const payload = await auth.verifyRefresh(data.refreshToken);
				if (payload === false) {
					throw new Error("Invalid refresh token");
				}

				// Type guard to ensure we have the right payload structure
				if (!payload.sessionId || payload.type !== "refresh") {
					throw new Error("Invalid refresh token format");
				}

				// Validate session
				const session = await sessionRepo.findById(payload.sessionId);
				if (
					!session ||
					!session.isValid ||
					new Date(session.expiresAt) <= new Date()
				) {
					throw new Error("Session expired or invalid");
				}

				// Get user
				const user = await userRepo.findById(payload.sub);
				if (!user) {
					throw new Error("User not found or inactive");
				}

				// Update session activity
				await sessionRepo.updateActivity(payload.sessionId);

				// Generate new tokens (use signTokens since signAccessToken doesn't exist)
				const tokens = await auth.signTokens({
					sub: user.id,
					email: user.email,
					username: user.username,
					sessionId: payload.sessionId,
				});

				return {
					tokens: {
						accessToken: tokens.accessToken,
						refreshToken: tokens.refreshToken, // Use new refresh token
						expiresIn: tokens.expiresIn,
					},
				};
			},

			/**
			 * Logout user (invalidate session)
			 */
			async logout(sessionId: string): Promise<void> {
				await sessionRepo.invalidate(sessionId);
			},

			/**
			 * Logout from all sessions
			 */
			async logoutAll(userId: string): Promise<void> {
				await sessionRepo.invalidateAllForUser(userId);
			},

			/**
			 * Send email verification
			 */
			async sendEmailVerification(userId: string): Promise<void> {
				const user = await userRepo.findById(userId);
				if (!user) {
					throw new Error("User not found");
				}

				if (user.emailVerified) {
					throw new Error("Email is already verified");
				}

				// Delete any existing verification tokens
				await emailVerificationTokenRepo.deleteAllForUser(userId);

				// Generate new verification token
				const token = emailVerificationTokenRepo.generateToken();
				const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000); // 24 hours

				// Create verification token
				await emailVerificationTokenRepo.create({
					user: { connect: { id: userId } },
					token,
					expiresAt,
				});

				// Send verification email
				await emailService.sendEmailVerification(
					user.email,
					user.firstName,
					token,
				);
			},

			/**
			 * Verify email address
			 */
			async verifyEmail(
				token: string,
			): Promise<{ user: Omit<User, "password"> }> {
				// Find valid token
				const verificationToken = await emailVerificationTokenRepo.findValidToken(token);
				if (!verificationToken) {
					throw new Error("Invalid or expired verification token");
				}

				// Update user as verified
				const user = await userRepo.update(verificationToken.userId, {
					emailVerified: true,
				});

				// Delete the verification token
				await emailVerificationTokenRepo.delete(verificationToken.id);

				// Send welcome email (optional)
				try {
					await emailService.sendWelcomeEmail(user.email, user.firstName);
				} catch (error) {
					// Don't fail the verification if welcome email fails
					console.warn("Failed to send welcome email:", error);
				}

				return { user };
			},

			/**
			 * Initiate password reset
			 */
			async initiatePasswordReset(email: string): Promise<void> {
				const user = await userRepo.findByEmail(email.toLowerCase().trim());
				if (!user) {
					// Don't reveal if user exists for security
					return;
				}

				// Delete any existing reset tokens
				await passwordResetTokenRepo.deleteAllForUser(user.id);

				// Generate new reset token
				const token = passwordResetTokenRepo.generateToken();
				const expiresAt = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

				// Create reset token
				await passwordResetTokenRepo.create({
					user: { connect: { id: user.id } },
					token,
					expiresAt,
					used: false,
				});

				// Send reset email
				await emailService.sendPasswordReset(
					user.email,
					user.firstName,
					token,
				);
			},

			/**
			 * Complete password reset
			 */
			async resetPassword(token: string, newPassword: string): Promise<void> {
				// Find valid token
				const resetToken = await passwordResetTokenRepo.findValidToken(token);
				if (!resetToken) {
					throw new Error("Invalid or expired reset token");
				}

				// Validate new password strength
				const passwordValidation = PasswordSecurity.validateStrength(newPassword);
				if (!passwordValidation.isValid) {
					throw new Error(
						`Password validation failed: ${passwordValidation.errors.join(", ")}`,
					);
				}

				// Hash new password
				const newPasswordHash = await PasswordSecurity.hash(newPassword);

				// Update user password
				await userRepo.updatePassword(resetToken.userId, newPasswordHash);

				// Mark token as used
				await passwordResetTokenRepo.markAsUsed(resetToken.id);

				// Invalidate all sessions for security
				await sessionRepo.invalidateAllForUser(resetToken.userId);
			},

			/**
			 * Change password (authenticated user)
			 */
			async changePassword(
				userId: string,
				currentPassword: string,
				newPassword: string,
			): Promise<void> {
				// Get user with password by first finding by ID and then using raw query for password
				const user = await userRepo.findById(userId);
				if (!user) {
					throw new Error("User not found");
				}

				// Get password hash separately (this requires a custom query)
				const userWithPassword = await userRepo.findByEmailWithPassword(
					user.email,
				);
				if (!userWithPassword || !userWithPassword.password) {
					throw new Error("User password not found");
				}

				// Verify current password
				const isValidPassword = await PasswordSecurity.verify(
					currentPassword,
					userWithPassword.password,
				);
				if (!isValidPassword) {
					throw new Error("Current password is incorrect");
				}

				// Validate new password strength
				const passwordValidation =
					PasswordSecurity.validateStrength(newPassword);
				if (!passwordValidation.isValid) {
					throw new Error(
						`Password validation failed: ${passwordValidation.errors.join(", ")}`,
					);
				}

				// Hash new password
				const newPasswordHash = await PasswordSecurity.hash(newPassword);

				// Update password using the updatePassword method
				await userRepo.updatePassword(userId, newPasswordHash);

				// Invalidate all sessions except current one (optional)
				// await this.logoutAll(userId);
			},

			/**
			 * Get user profile by ID
			 */
			async getProfile(
				userId: string,
			): Promise<{ user: Omit<User, "password"> }> {
				const user = await userRepo.findById(userId);
				if (!user) {
					throw new Error("User not found");
				}

				return { user };
			},

			/**
			 * Update user profile
			 */
			async updateProfile(
				userId: string,
				updates: Partial<Pick<User, "firstName" | "lastName" | "username">>,
			): Promise<{ user: Omit<User, "password"> }> {
				const user = await userRepo.update(userId, updates);
				return { user };
			},
		},
	}))
	.as("scoped");
