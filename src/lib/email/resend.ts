import type { ReactNode } from "react";
import { Resend } from "resend";

// FIXME: Create a utility to get environment variables
const resend = new Resend(process.env.RESEND_API_KEY);

interface EmailOptions {
	to: string;
	subject: string;
	react: ReactNode;
}

async function sendEmail(options: EmailOptions): Promise<{ id: string }> {
	try {
		const { data, error } = await resend.emails.send({
			// FIXME: Move this to config
			from: "Tamatar <auth@email.tamatar.dev>",
			...options,
		});
		if (error || !data) {
			// TODO: Throw EmailError
			console.error("Error sending email:", error);
			throw new Error("Failed to send email");
		}
		return data;
	} catch (error) {
		// TODO: Throw EmailError
		console.error("Error sending email:", error);
		throw new Error("Failed to send email");
	}
}

export { sendEmail };
