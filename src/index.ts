import bearer from "@elysiajs/bearer";
import jwt from "@elysiajs/jwt";
import swagger from "@elysiajs/swagger";
import { Elysia } from "elysia";

const app = new Elysia()
	.use(swagger())
	.use(bearer())
	.use(
		jwt({
			// FIXME: Create a utility to get environment variables
			secret: process.env.JWT_SECRET || "secret",
		}),
	)
	.get("/", () => "Hello Elysia")
	.get("/health", () => {
		return { status: "ok", timestamp: new Date().toISOString() };
	})
	.post("/login", () => {
		// TODO: Implement login logic
		return { message: "Login endpoint" };
	})
	.post("/register", () => {
		// TODO: Implement registration logic
		return { message: "Register endpoint" };
	})
	.get("/logout", () => {
		// TODO: Implement logout logic
		return { message: "Logout endpoint" };
	})
	.listen(3000);

console.log(
	`🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`,
);
