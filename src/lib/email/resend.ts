import { Elysia } from "elysia";
import type { ReactNode } from "react";
import { Resend } from "resend";
import { configPlugin } from "../config/plugin";
import { EmailVerificationTemplate } from "./templates/email-verification";
import { PasswordResetTemplate } from "./templates/password-reset";

interface EmailOptions {
	to: string;
	subject: string;
	react: ReactNode;
}

export const emailService = new Elysia({ name: "email-service" })
	.use(configPlugin)
	.derive(({ config }) => {
		const resend = new Resend(config.email.resendApiKey);

		return {
			emailService: {
				/**
				 * Send a generic email
				 */
				async sendEmail(options: EmailOptions): Promise<{ id: string }> {
					try {
						const { data, error } = await resend.emails.send({
							from: config.email.fromEmail,
							replyTo: config.email.replyToEmail,
							...options,
						});

						if (error || !data) {
							console.error("Error sending email:", error);
							throw new Error("Failed to send email");
						}

						return data;
					} catch (error) {
						console.error("Error sending email:", error);
						throw new Error("Failed to send email");
					}
				},

				/**
				 * Send email verification email
				 */
				async sendEmailVerification(
					to: string,
					firstName: string,
					verificationToken: string,
				): Promise<{ id: string }> {
					if (!config.email.verificationEnabled) {
						throw new Error("Email verification is disabled");
					}

					const verificationUrl = `${config.urls.frontendService}/verify-email?token=${verificationToken}`;

					return await this.sendEmail({
						to,
						subject: "Verify your email address - Tamatar",
						react: EmailVerificationTemplate({
							firstName,
							verificationUrl,
							expiresIn: "24 hours",
						}),
					});
				},

				/**
				 * Send password reset email
				 */
				async sendPasswordReset(
					to: string,
					firstName: string,
					resetToken: string,
				): Promise<{ id: string }> {
					if (!config.email.passwordResetEnabled) {
						throw new Error("Password reset is disabled");
					}

					const resetUrl = `${config.urls.frontendService}/reset-password?token=${resetToken}`;

					return await this.sendEmail({
						to,
						subject: "Reset your password - Tamatar",
						react: PasswordResetTemplate({
							firstName,
							resetUrl,
							expiresIn: "1 hour",
						}),
					});
				},

				/**
				 * Send welcome email after successful verification
				 */
				async sendWelcomeEmail(
					to: string,
					firstName: string,
				): Promise<{ id: string }> {
					return await this.sendEmail({
						to,
						subject: "Welcome to Tamatar!",
						react: EmailVerificationTemplate({
							firstName,
							verificationUrl: config.urls.frontendService,
							expiresIn: "Never",
						}),
					});
				},
			},
		};
	})
	.as("scoped");
