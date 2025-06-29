import { Elysia } from "elysia";
import { databasePlugin } from "./plugin";
import { EmailVerificationTokenRepository } from "./email-verification-token";
import { PasswordResetTokenRepository } from "./password-reset-token";
import { SessionRepository } from "./session";
import { UserRepository } from "./user";

export const repositoryPlugin = new Elysia({ name: "repositories" })
	.use(databasePlugin)
	.derive(({ db }) => ({
		userRepo: new UserRepository(db),
		sessionRepo: new SessionRepository(db),
		emailVerificationTokenRepo: new EmailVerificationTokenRepository(db),
		passwordResetTokenRepo: new PasswordResetTokenRepository(db),
	}))
	.as("scoped");
