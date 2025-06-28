import { t } from "elysia";
import { __nullable__ } from "./__nullable__";
import { __transformDate__ } from "./__transformDate__";

export const SessionPlain = t.Object(
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
);

export const SessionRelations = t.Object(
	{
		user: t.Object(
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
		),
	},
	{ additionalProperties: false },
);

export const SessionPlainInputCreate = t.Object(
	{
		userAgent: t.Optional(__nullable__(t.String())),
		ipAddress: t.Optional(__nullable__(t.String())),
		expiresAt: t.Date(),
	},
	{ additionalProperties: false },
);

export const SessionPlainInputUpdate = t.Object(
	{
		userAgent: t.Optional(__nullable__(t.String())),
		ipAddress: t.Optional(__nullable__(t.String())),
		expiresAt: t.Optional(t.Date()),
	},
	{ additionalProperties: false },
);

export const SessionRelationsInputCreate = t.Object(
	{
		user: t.Object(
			{
				connect: t.Object(
					{
						id: t.String({ additionalProperties: false }),
					},
					{ additionalProperties: false },
				),
			},
			{ additionalProperties: false },
		),
	},
	{ additionalProperties: false },
);

export const SessionRelationsInputUpdate = t.Partial(
	t.Object(
		{
			user: t.Object(
				{
					connect: t.Object(
						{
							id: t.String({ additionalProperties: false }),
						},
						{ additionalProperties: false },
					),
				},
				{ additionalProperties: false },
			),
		},
		{ additionalProperties: false },
	),
);

export const SessionWhere = t.Partial(
	t.Recursive(
		(Self) =>
			t.Object(
				{
					AND: t.Union([Self, t.Array(Self, { additionalProperties: false })]),
					NOT: t.Union([Self, t.Array(Self, { additionalProperties: false })]),
					OR: t.Array(Self, { additionalProperties: false }),
					id: t.String(),
					userId: t.String(),
					userAgent: t.String(),
					ipAddress: t.String(),
					isValid: t.Boolean(),
					expiresAt: t.Date(),
					createdAt: t.Date(),
					updatedAt: t.Date(),
				},
				{ additionalProperties: false },
			),
		{ $id: "Session" },
	),
);

export const SessionWhereUnique = t.Recursive(
	(Self) =>
		t.Intersect(
			[
				t.Partial(
					t.Object({ id: t.String() }, { additionalProperties: false }),
					{ additionalProperties: false },
				),
				t.Union([t.Object({ id: t.String() })], {
					additionalProperties: false,
				}),
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
							userId: t.String(),
							userAgent: t.String(),
							ipAddress: t.String(),
							isValid: t.Boolean(),
							expiresAt: t.Date(),
							createdAt: t.Date(),
							updatedAt: t.Date(),
						},
						{ additionalProperties: false },
					),
				),
			],
			{ additionalProperties: false },
		),
	{ $id: "Session" },
);

export const SessionSelect = t.Partial(
	t.Object(
		{
			id: t.Boolean(),
			userId: t.Boolean(),
			user: t.Boolean(),
			userAgent: t.Boolean(),
			ipAddress: t.Boolean(),
			isValid: t.Boolean(),
			expiresAt: t.Boolean(),
			createdAt: t.Boolean(),
			updatedAt: t.Boolean(),
			_count: t.Boolean(),
		},
		{ additionalProperties: false },
	),
);

export const SessionInclude = t.Partial(
	t.Object(
		{ user: t.Boolean(), _count: t.Boolean() },
		{ additionalProperties: false },
	),
);

export const SessionOrderBy = t.Partial(
	t.Object(
		{
			id: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			userId: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			userAgent: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			ipAddress: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			isValid: t.Union([t.Literal("asc"), t.Literal("desc")], {
				additionalProperties: false,
			}),
			expiresAt: t.Union([t.Literal("asc"), t.Literal("desc")], {
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

export const Session = t.Composite([SessionPlain, SessionRelations], {
	additionalProperties: false,
});

export const SessionInputCreate = t.Composite(
	[SessionPlainInputCreate, SessionRelationsInputCreate],
	{ additionalProperties: false },
);

export const SessionInputUpdate = t.Composite(
	[SessionPlainInputUpdate, SessionRelationsInputUpdate],
	{ additionalProperties: false },
);
