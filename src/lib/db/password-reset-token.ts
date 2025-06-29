import type { PrismaClient, PasswordResetToken, Prisma } from "../../generated/prisma";

export class PasswordResetTokenRepository {
	constructor(private db: PrismaClient) {}

	/**
	 * Create a new password reset token
	 */
	async create(data: Prisma.PasswordResetTokenCreateInput): Promise<PasswordResetToken> {
		return await this.db.passwordResetToken.create({
			data,
		});
	}

	/**
	 * Find a valid token by token string
	 */
	async findValidToken(token: string): Promise<PasswordResetToken | null> {
		return await this.db.passwordResetToken.findFirst({
			where: {
				token,
				used: false,
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
	async findByUserId(userId: string): Promise<PasswordResetToken | null> {
		return await this.db.passwordResetToken.findFirst({
			where: {
				userId,
				used: false,
			},
			orderBy: {
				createdAt: 'desc',
			},
		});
	}

	/**
	 * Mark token as used
	 */
	async markAsUsed(id: string): Promise<PasswordResetToken> {
		return await this.db.passwordResetToken.update({
			where: { id },
			data: { used: true },
		});
	}

	/**
	 * Delete token
	 */
	async delete(id: string): Promise<PasswordResetToken> {
		return await this.db.passwordResetToken.delete({
			where: { id },
		});
	}

	/**
	 * Delete all tokens for a user
	 */
	async deleteAllForUser(userId: string): Promise<void> {
		await this.db.passwordResetToken.deleteMany({
			where: { userId },
		});
	}

	/**
	 * Delete expired or used tokens (cleanup)
	 */
	async deleteExpired(): Promise<void> {
		await this.db.passwordResetToken.deleteMany({
			where: {
				OR: [
					{
						expiresAt: {
							lt: new Date(),
						},
					},
					{
						used: true,
						createdAt: {
							lt: new Date(Date.now() - 24 * 60 * 60 * 1000), // 24 hours ago
						},
					},
				],
			},
		});
	}

	/**
	 * Generate a unique reset token
	 */
	generateToken(): string {
		// Generate a secure random token
		const bytes = new Uint8Array(32);
		crypto.getRandomValues(bytes);
		return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
	}
}
