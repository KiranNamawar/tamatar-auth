import { type TSchema, t } from "elysia";
export const __nullable__ = <T extends TSchema>(schema: T) =>
	t.Union([t.Null(), schema]);
