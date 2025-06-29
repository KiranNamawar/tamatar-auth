import type { Prisma, Session } from "../../generated/prisma";
import prisma from "./prisma";

function createSession(data: Prisma.SessionCreateInput): Promise<Session> {
	try {
		return prisma.session.create({
			data,
		});
	} catch (error) {
		// TODO: Throw DatabaseError
		console.error("Error creating session:", error);
		throw new Error("Failed to create session");
	}
}

function getSession(id: string): Promise<Session | null> {
	try {
		return prisma.session.findUnique({
			where: { id },
		});
	} catch (error) {
		// TODO: Throw DatabaseError
		console.error("Error fetching session:", error);
		throw new Error("Failed to fetch session");
	}
}

function deleteSession(id: string): Promise<Session | null> {
	try {
		return prisma.session.delete({
			where: { id },
		});
	} catch (error) {
		// TODO: Throw DatabaseError
		console.error("Error deleting session:", error);
		throw new Error("Failed to delete session");
	}
}

export { createSession, getSession, deleteSession };
