import type { Prisma, PrismaClient, User } from "../../generated/prisma";

export class UserRepository {
	constructor(private db: PrismaClient) {}

	// Safe user fields (excluding password)
	private get userSelectFields() {
		return {
			id: true,
			firstName: true,
			lastName: true,
			avatar: true,
			username: true,
			email: true,
			googleId: true,
			emailVerified: true,
			createdAt: true,
			updatedAt: true,
			// Never select password in responses
			password: false,
		} satisfies Prisma.UserSelect;
	}

	async create(data: Prisma.UserCreateInput): Promise<Omit<User, "password">> {
		return await this.db.user.create({
			data,
			select: this.userSelectFields,
		});
	}

	async findById(id: string): Promise<Omit<User, "password"> | null> {
		return await this.db.user.findUnique({
			where: { id },
			select: this.userSelectFields,
		});
	}

	async findByEmail(email: string): Promise<Omit<User, "password"> | null> {
		return await this.db.user.findUnique({
			where: { email: email.toLowerCase().trim() },
			select: this.userSelectFields,
		});
	}

	async findByUsername(
		username: string,
	): Promise<Omit<User, "password"> | null> {
		return await this.db.user.findUnique({
			where: { username: username.toLowerCase().trim() },
			select: this.userSelectFields,
		});
	}

	async findByGoogleId(
		googleId: string,
	): Promise<Omit<User, "password"> | null> {
		return await this.db.user.findUnique({
			where: { googleId },
			select: this.userSelectFields,
		});
	}

	// For authentication - includes password hash
	async findByEmailWithPassword(email: string): Promise<User | null> {
		return await this.db.user.findUnique({
			where: { email: email.toLowerCase().trim() },
		});
	}

	async update(
		id: string,
		data: Prisma.UserUpdateInput,
	): Promise<Omit<User, "password">> {
		return await this.db.user.update({
			where: { id },
			data,
			select: this.userSelectFields,
		});
	}

	async updatePassword(id: string, hashedPassword: string): Promise<void> {
		await this.db.user.update({
			where: { id },
			data: { password: hashedPassword },
		});
	}

	async verifyEmail(id: string): Promise<Omit<User, "password">> {
		return await this.db.user.update({
			where: { id },
			data: { emailVerified: true },
			select: this.userSelectFields,
		});
	}

	async delete(id: string): Promise<Omit<User, "password">> {
		return await this.db.user.delete({
			where: { id },
			select: this.userSelectFields,
		});
	}

	async findMany(params: {
		skip?: number;
		take?: number;
		where?: Prisma.UserWhereInput;
		orderBy?: Prisma.UserOrderByWithRelationInput;
	}): Promise<{ users: Omit<User, "password">[]; total: number }> {
		const [users, total] = await Promise.all([
			this.db.user.findMany({
				...params,
				select: this.userSelectFields,
			}),
			this.db.user.count({ where: params.where }),
		]);

		return { users, total };
	}

	async exists(email: string): Promise<boolean> {
		const user = await this.db.user.findUnique({
			where: { email: email.toLowerCase().trim() },
			select: { id: true },
		});
		return !!user;
	}

	async existsByUsername(username: string): Promise<boolean> {
		const user = await this.db.user.findUnique({
			where: { username: username.toLowerCase().trim() },
			select: { id: true },
		});
		return !!user;
	}
}
