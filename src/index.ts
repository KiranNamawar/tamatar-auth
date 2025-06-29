import { configPlugin } from "./lib/config/plugin";
import { Elysia } from "elysia";
import { publicRoutes } from "./routes/public";
import { emailRoutes } from "./routes/email";
import { userRoutes } from "./routes/user";
import { repositoryPlugin } from "./lib/db/repositories";
import swagger from "@elysiajs/swagger";

const app = new Elysia({ name: "tamatar-auth" })
	.use(configPlugin)
	.use(
		swagger({
			documentation: {
				info: {
					title: "Tamatar Auth API",
					version: "1.0.0",
					description: "Authentication microservice for the Tamatar ecosystem built with Elysia.js",
					contact: {
						name: "Tamatar Team",
						email: "support@tamatar.dev",
					},
					license: {
						name: "MIT",
					},
				},
				servers: [
					{
						url: "http://localhost:3000",
						description: "Development server",
					},
				],
				components: {
					securitySchemes: {
						BearerAuth: {
							type: "http",
							scheme: "bearer",
							bearerFormat: "JWT",
							description: "JWT token for authentication. Format: Bearer <token>",
						},
					},
				},
				// Security should be defined per-route, not globally
				// This allows public routes to not require authentication
				tags: [
					{ 
						name: "Authentication", 
						description: "User authentication and registration endpoints" 
					},
					{ 
						name: "User Management", 
						description: "User profile and management endpoints" 
					},
					{ 
						name: "Session Management", 
						description: "Session and token management endpoints" 
					},
					{ 
						name: "Health", 
						description: "Health check and monitoring endpoints" 
					},
					{ 
						name: "Development", 
						description: "Development and testing endpoints" 
					},
				],
			},
			path: "/swagger",
		}),
	)
	.use(repositoryPlugin)
	.use(publicRoutes)
	.use(emailRoutes)
	.use(userRoutes)
	.get("/", () => "Hello Elysia")
	.get(
		"/health",
		async ({ config, db }) => {
			// Perform database health check
			let dbHealthy = false;
			try {
				await db.$queryRaw`SELECT 1`;
				dbHealthy = true;
			} catch {
				dbHealthy = false;
			}

			return {
				status: dbHealthy ? "ok" : "degraded",
				timestamp: new Date().toISOString(),
				environment: config.nodeEnv,
				version: "1.0.0",
				database: {
					status: dbHealthy ? "connected" : "disconnected",
				},
			};
		},
		{
			detail: {
				tags: ["Health"],
				summary: "Health check endpoint",
				description: "Check the health status of the API and database connection",
				responses: {
					200: {
						description: "Health check successful",
						content: {
							"application/json": {
								schema: {
									type: "object",
									properties: {
										status: { type: "string", enum: ["ok", "degraded"] },
										timestamp: { type: "string", format: "date-time" },
										environment: { type: "string" },
										version: { type: "string" },
										database: {
											type: "object",
											properties: {
												status: { type: "string", enum: ["connected", "disconnected"] }
											}
										}
									}
								}
							}
						}
					}
				}
			},
		},
	)
	// Sample database endpoints to test our repository layer
	.get(
		"/users",
		async ({ userRepo, query }) => {
			const page = Number(query.page) || 1;
			const limit = Number(query.limit) || 10;
			const skip = (page - 1) * limit;

			const result = await userRepo.findMany({
				skip,
				take: limit,
				orderBy: { createdAt: "desc" },
			});

			return {
				users: result.users,
				pagination: {
					page,
					limit,
					total: result.total,
					totalPages: Math.ceil(result.total / limit),
				},
			};
		},
		{
			detail: {
				tags: ["Development"],
				summary: "List all users",
				description: "Retrieve a paginated list of users (development endpoint)",
			},
		},
	)
	.get(
		"/users/:id",
		async ({ userRepo, params, error }) => {
			const user = await userRepo.findById(params.id);

			if (!user) {
				return error(404, "User not found");
			}

			return { user };
		},
		{
			detail: {
				tags: ["Development"],
				summary: "Get user by ID",
				description: "Retrieve a specific user by their ID (development endpoint)",
			},
		},
	)
	.get(
		"/sessions/user/:userId",
		async ({ sessionRepo, params }) => {
			const sessions = await sessionRepo.findByUserId(params.userId, {
				limit: 10,
			});

			return { sessions };
		},
		{
			detail: {
				tags: ["Development"],
				summary: "Get user sessions",
				description: "Retrieve active sessions for a user (development endpoint)",
			},
		},
	)
	.onStart(() => {
		// Configuration is already logged by configPlugin
		console.log(`🦊 Tamatar Auth server started successfully`);
		console.log(`🚀 API Documentation: http://localhost:3000/swagger`);
	})
	.listen(3000);

console.log(
	`🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`,
);
