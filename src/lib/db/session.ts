import type { Prisma, PrismaClient, Session } from "../../generated/prisma";

export class SessionRepository {
	constructor(private db: PrismaClient) {}

	async create(data: Prisma.SessionCreateInput): Promise<Session> {
		return await this.db.session.create({
			data,
			include: {
				user: {
					select: {
						id: true,
						email: true,
						firstName: true,
						lastName: true,
						emailVerified: true,
					},
				},
			},
		});
	}

	async findById(id: string): Promise<Session | null> {
		return await this.db.session.findUnique({
			where: { id },
			include: {
				user: {
					select: {
						id: true,
						email: true,
						firstName: true,
						lastName: true,
						emailVerified: true,
					},
				},
			},
		});
	}

	async findValidById(id: string): Promise<Session | null> {
		return await this.db.session.findFirst({
			where: {
				id,
				isValid: true,
				expiresAt: {
					gt: new Date(),
				},
			},
			include: {
				user: {
					select: {
						id: true,
						email: true,
						firstName: true,
						lastName: true,
						emailVerified: true,
					},
				},
			},
		});
	}

	async findByUserId(
		userId: string,
		options?: {
			includeExpired?: boolean;
			includeInvalid?: boolean;
			limit?: number;
		},
	): Promise<Session[]> {
		const {
			includeExpired = false,
			includeInvalid = false,
			limit,
		} = options || {};

		const where: Prisma.SessionWhereInput = {
			userId,
		};

		if (!includeInvalid) {
			where.isValid = true;
		}

		if (!includeExpired) {
			where.expiresAt = { gt: new Date() };
		}

		return await this.db.session.findMany({
			where,
			orderBy: { createdAt: "desc" },
			take: limit,
			include: {
				user: {
					select: {
						id: true,
						email: true,
						firstName: true,
						lastName: true,
						emailVerified: true,
					},
				},
			},
		});
	}

	async invalidateSession(id: string): Promise<Session> {
		return await this.db.session.update({
			where: { id },
			data: { isValid: false },
			include: {
				user: {
					select: {
						id: true,
						email: true,
						firstName: true,
						lastName: true,
						emailVerified: true,
					},
				},
			},
		});
	}

	async invalidateAllUserSessions(userId: string): Promise<{ count: number }> {
		return await this.db.session.updateMany({
			where: {
				userId,
				isValid: true,
			},
			data: { isValid: false },
		});
	}

	async extendSession(id: string, expiresAt: Date): Promise<Session> {
		return await this.db.session.update({
			where: { id },
			data: { expiresAt },
			include: {
				user: {
					select: {
						id: true,
						email: true,
						firstName: true,
						lastName: true,
						emailVerified: true,
					},
				},
			},
		});
	}

	async cleanupExpiredSessions(): Promise<{ count: number }> {
		return await this.db.session.deleteMany({
			where: {
				expiresAt: {
					lt: new Date(),
				},
			},
		});
	}

	async getActiveSessionCount(userId: string): Promise<number> {
		return await this.db.session.count({
			where: {
				userId,
				isValid: true,
				expiresAt: {
					gt: new Date(),
				},
			},
		});
	}

	async delete(id: string): Promise<Session> {
		return await this.db.session.delete({
			where: { id },
			include: {
				user: {
					select: {
						id: true,
						email: true,
						firstName: true,
						lastName: true,
						emailVerified: true,
					},
				},
			},
		});
	}

	async invalidate(id: string): Promise<Session> {
		return await this.invalidateSession(id);
	}

	async invalidateAllForUser(userId: string): Promise<void> {
		await this.db.session.updateMany({
			where: { userId, isValid: true },
			data: { isValid: false },
		});
	}

	async updateActivity(id: string): Promise<Session> {
		// Since we don't have lastActivityAt in the schema, we'll update the updatedAt field
		return await this.db.session.update({
			where: { id },
			data: { updatedAt: new Date() },
		});
	}

	// Get sessions for admin/monitoring purposes
	async findMany(params: {
		skip?: number;
		take?: number;
		where?: Prisma.SessionWhereInput;
		orderBy?: Prisma.SessionOrderByWithRelationInput;
	}): Promise<{ sessions: Session[]; total: number }> {
		const [sessions, total] = await Promise.all([
			this.db.session.findMany({
				...params,
				include: {
					user: {
						select: {
							id: true,
							email: true,
							firstName: true,
							lastName: true,
							emailVerified: true,
						},
					},
				},
			}),
			this.db.session.count({ where: params.where }),
		]);

		return { sessions, total };
	}
}
