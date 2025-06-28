import { t } from "elysia";
import { __nullable__ } from "./__nullable__";
import { __transformDate__ } from "./__transformDate__";

export const UserPlain = t.Object(
	{
		id: t.String(),
		firstName: t.String(),
		lastName: __nullable__(t.String()),
		avatar: __nullable__(t.String()),
		username: t.String(),
		email: t.String(),
		password: __nullable__(t.String()),
		googleId: __nullable__(t.String()),
		emailVerified: t.Boolean(),
		createdAt: t.Date(),
		updatedAt: t.Date(),
	},
	{ additionalProperties: false },
);

export const UserRelations = t.Object(
	{
		sessions: t.Array(
			t.Object(
				{
					id: t.String(),
					userId: t.String(),
					userAgent: __nullable__(t.String()),
					ipAddress: __nullable__(t.String()),
					isValid: t.Boolean(),
					expiresAt: t.Date(),
					createdAt: t.Date(),
					updatedAt: t.Date(),
				},
				{ additionalProperties: false },
			),
			{ additionalProperties: false },
		),
	},
	{ additionalProperties: false },
);

export const UserPlainInputCreate = t.Object(
	{
		firstName: t.String(),
		lastName: t.Optional(__nullable__(t.String())),
		avatar: t.Optional(__nullable__(t.String())),
		username: t.String(),
		email: t.String(),
		password: t.Optional(__nullable__(t.String())),
		emailVerified: t.Optional(t.Boolean()),
	},
	{ additionalProperties: false },
);

export const UserPlainInputUpdate = t.Object(
	{
		firstName: t.Optional(t.String()),
		lastName: t.Optional(__nullable__(t.String())),
		avatar: t.Optional(__nullable__(t.String())),
		username: t.Optional(t.String()),
		email: t.Optional(t.String()),
		password: t.Optional(__nullable__(t.String())),
		emailVerified: t.Optional(t.Boolean()),
	},
	{ additionalProperties: false },
);

export const UserRelationsInputCreate = t.Object(
	{
		sessions: t.Optional(
			t.Object(
				{
					connect: t.Array(
						t.Object(
							{
								id: t.String({ additionalProperties: false }),
							},
							{ additionalProperties: false },
						),
						{ additionalProperties: false },
					),
				},
				{ additionalProperties: false },
			),
		),
	},
	{ additionalProperties: false },
);

export const UserRelationsInputUpdate = t.Partial(
	t.Object(
		{
			sessions: t.Partial(
				t.Object(
					{
						connect: t.Array(
							t.Object(
								{
									id: t.String({ additionalProperties: false }),
								},
								{ additionalProperties: false },
							),
							{ additionalProperties: false },
						),
						disconnect: t.Array(
							t.Object(
								{
									id: t.String({ additionalProperties: false }),
								},
								{ additionalProperties: false },
							),
							{ additionalProperties: false },
						),
					},
					{ additionalProperties: false },
				),
			),
		},
		{ additionalProperties: false },
	),
);

export const UserWhere = t.Partial(
	t.Recursive(
		(Self) =>
			t.Object(
				{
					AND: t.Union([Self, t.Array(Self, { additionalProperties: false })]),
					NOT: t.Union([Self, t.Array(Self, { additionalProperties: false })]),
					OR: t.Array(Self, { additionalProperties: false }),
					id: t.String(),
					firstName: t.String(),
					lastName: t.String(),
					avatar: t.String(),
					username: t.String(),
					email: t.String(),
					password: t.String(),
					googleId: t.String(),
					emailVerified: t.Boolean(),
					createdAt: t.Date(),
					updatedAt: t.Date(),
				},
				{ additionalProperties: false },
			),
		{ $id: "User" },
	),
);

export const UserWhereUnique = t.Recursive(
	(Self) =>
		t.Intersect(
			[
				t.Partial(
					t.Object(
						{
							id: t.String(),
							username: t.String(),
							email: t.String(),
							googleId: t.String(),
						},
						{ additionalProperties: false },
					),
					{ additionalProperties: false },
				),
				t.Union(
					[
						t.Object({ id: t.String() }),
						t.Object({ username: t.String() }),
						t.Object({ email: t.String() }),
						t.Object({ googleId: t.String() }),
					],
					{ additionalProperties: false },
				),
				t.Partial(
					t.Object({
						AND: t.Union([
							Self,
							t.Array(Self, { additionalProperties: false }),
						]),
						NOT: t.Union([
							Self,
							t.Array(Self, { additionalProperties: false }),
						]),
						OR: t.Array(Self, { additionalProperties: false }),
					}),
					{ additionalProperties: false },
				),
				t.Partial(
					t.Object(
						{
							id: t.String(),
							firstName: t.String(),
							lastName: t.String(),
							avatar: t.String(),
							username: t.String(),
							email: t.String(),
							password: t.String(),
							googleId: t.String(),
							emailVerified: t.Boolean(),
							createdAt: t.Date(),
							updatedAt: t.Date(),
						},
						{ additionalProperties: false },
					),
				),
			],
			{ additionalProperties: false },
		),
	{ $id: "User" },
);

export const UserSelect = t.Partial(
	t.Object(
		{
			id: t.Boolean(),
			firstName: t.Boolean(),
			lastName: t.Boolean(),
			avatar: t.Boolean(),
			username: t.Boolean(),
			email: t.Boolean(),
			password: t.Boolean(),
			googleId: t.Boolean(),
			emailVerified: t.Boolean(),
			createdAt: t.Boolean(),
			updatedAt: t.Boolean(),
			sessions: t.Boolean(),
			_count: t.Boolean(),
		},
		{ additionalProperties: false },
	),
);

export const UserInclude = t.Partial(
	t.Object(
		{ sessions: t.Boolean(), _count: t.Boolean() },
		{ additionalProperties: false },
	),
);

export const UserOrderBy = t.Partial(
	t.Object(
		{
			id: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			firstName: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			lastName: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			avatar: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			username: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			email: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			password: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			googleId: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			emailVerified: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			createdAt: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			updatedAt: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
		},
		{ additionalProperties: false },
	),
);

export const User = t.Composite([UserPlain, UserRelations], {
	additionalProperties: false,
});

export const UserInputCreate = t.Composite(
	[UserPlainInputCreate, UserRelationsInputCreate],
	{ additionalProperties: false },
);

export const UserInputUpdate = t.Composite(
	[UserPlainInputUpdate, UserRelationsInputUpdate],
	{ additionalProperties: false },
);
