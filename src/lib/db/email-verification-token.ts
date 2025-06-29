import type { PrismaClient, EmailVerificationToken, Prisma } from "../../generated/prisma";

export class EmailVerificationTokenRepository {
	constructor(private db: PrismaClient) {}

	/**
	 * Create a new email verification token
	 */
	async create(data: Prisma.EmailVerificationTokenCreateInput): Promise<EmailVerificationToken> {
		return await this.db.emailVerificationToken.create({
			data,
		});
	}

	/**
	 * Find a valid token by token string
	 */
	async findValidToken(token: string): Promise<EmailVerificationToken | null> {
		return await this.db.emailVerificationToken.findFirst({
			where: {
				token,
				expiresAt: {
					gt: new Date(),
				},
			},
			include: {
				user: true,
			},
		});
	}

	/**
	 * Find token by user ID (get the latest one)
	 */
	async findByUserId(userId: string): Promise<EmailVerificationToken | null> {
		return await this.db.emailVerificationToken.findFirst({
			where: {
				userId,
			},
			orderBy: {
				createdAt: 'desc',
			},
		});
	}

	/**
	 * Delete token (after successful verification)
	 */
	async delete(id: string): Promise<EmailVerificationToken> {
		return await this.db.emailVerificationToken.delete({
			where: { id },
		});
	}

	/**
	 * Delete all tokens for a user
	 */
	async deleteAllForUser(userId: string): Promise<void> {
		await this.db.emailVerificationToken.deleteMany({
			where: { userId },
		});
	}

	/**
	 * Delete expired tokens (cleanup)
	 */
	async deleteExpired(): Promise<void> {
		await this.db.emailVerificationToken.deleteMany({
			where: {
				expiresAt: {
					lt: new Date(),
				},
			},
		});
	}

	/**
	 * Generate a unique verification token
	 */
	generateToken(): string {
		// Generate a secure random token
		const bytes = new Uint8Array(32);
		crypto.getRandomValues(bytes);
		return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
	}
}
