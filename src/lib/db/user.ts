import type { Prisma, User } from "../../generated/prisma";
import prisma from "./prisma";

function createUser(data: Prisma.UserCreateInput): Promise<User> {
	try {
		return prisma.user.create({
			data,
		});
	} catch (error) {
		// TODO: Throw DatabaseError
		console.error("Error creating user:", error);
		throw new Error("Failed to create user");
	}
}

function getUserByEmail(email: string): Promise<User | null> {
	try {
		return prisma.user.findUnique({
			where: { email },
		});
	} catch (error) {
		// TODO: Throw DatabaseError
		console.error("Error fetching user by email:", error);
		throw new Error("Failed to fetch user");
	}
}

function getUserById(id: string): Promise<User | null> {
	try {
		return prisma.user.findUnique({
			where: { id },
		});
	} catch (error) {
		// TODO: Throw DatabaseError
		console.error("Error fetching user by ID:", error);
		throw new Error("Failed to fetch user");
	}
}

function updateUser(id: string, data: Prisma.UserUpdateInput): Promise<User> {
	try {
		return prisma.user.update({
			where: { id },
			data,
		});
	} catch (error) {
		// TODO: Throw DatabaseError
		console.error("Error updating user:", error);
		throw new Error("Failed to update user");
	}
}

function deleteUser(id: string): Promise<User> {
	try {
		return prisma.user.delete({
			where: { id },
		});
	} catch (error) {
		// TODO: Throw DatabaseError
		console.error("Error deleting user:", error);
		throw new Error("Failed to delete user");
	}
}

export { createUser, getUserByEmail, getUserById, updateUser, deleteUser };
