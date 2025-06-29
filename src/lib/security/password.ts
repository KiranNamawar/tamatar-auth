/**
 * Password security utilities using Bun's built-in password hashing
 * Bun provides bcrypt-compatible password hashing out of the box
 */

export interface PasswordValidationResult {
	isValid: boolean;
	score: number; // 0-4, where 4 is strongest
	errors: string[];
	suggestions: string[];
}

export class PasswordSecurity {
	/**
	 * Hash a password using Bun's built-in password hashing (bcrypt)
	 */
	static async hash(password: string): Promise<string> {
		return await Bun.password.hash(password, {
			algorithm: "bcrypt",
			cost: 12, // Recommended cost for production
		});
	}

	/**
	 * Verify a password against its hash
	 */
	static async verify(password: string, hash: string): Promise<boolean> {
		return await Bun.password.verify(password, hash);
	}

	/**
	 * Validate password strength
	 */
	static validateStrength(password: string): PasswordValidationResult {
		const errors: string[] = [];
		const suggestions: string[] = [];
		let score = 0;

		// Length check
		if (password.length < 8) {
			errors.push("Password must be at least 8 characters long");
		} else if (password.length >= 8) {
			score += 1;
		}

		if (password.length >= 12) {
			score += 1;
		}

		// Character variety checks
		const hasLowercase = /[a-z]/.test(password);
		const hasUppercase = /[A-Z]/.test(password);
		const hasNumbers = /\d/.test(password);
		const hasSpecialChars = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(
			password,
		);

		if (!hasLowercase) {
			errors.push("Password must contain at least one lowercase letter");
		}
		if (!hasUppercase) {
			errors.push("Password must contain at least one uppercase letter");
		}
		if (!hasNumbers) {
			errors.push("Password must contain at least one number");
		}
		if (!hasSpecialChars) {
			errors.push("Password must contain at least one special character");
		}

		// Award points for character variety
		const varietyCount = [
			hasLowercase,
			hasUppercase,
			hasNumbers,
			hasSpecialChars,
		].filter(Boolean).length;
		score += Math.max(0, varietyCount - 2); // Bonus points for 3+ types

		// Common password check
		if (PasswordSecurity.isCommonPassword(password)) {
			errors.push(
				"Password is too common, please choose a more unique password",
			);
			score = Math.max(0, score - 2);
		}

		// Pattern checks
		if (PasswordSecurity.hasWeakPatterns(password)) {
			errors.push(
				"Password contains weak patterns (repeated or sequential characters)",
			);
			score = Math.max(0, score - 1);
		}

		// Add suggestions
		if (password.length < 12) {
			suggestions.push("Use at least 12 characters for better security");
		}
		if (varietyCount < 4) {
			suggestions.push(
				"Include uppercase, lowercase, numbers, and special characters",
			);
		}
		if (
			!PasswordSecurity.hasWeakPatterns(password) &&
			varietyCount >= 3 &&
			password.length >= 12
		) {
			suggestions.push("Consider using a passphrase with multiple words");
		}

		return {
			isValid: errors.length === 0 && score >= 3,
			score: Math.min(4, score),
			errors,
			suggestions,
		};
	}

	/**
	 * Generate a secure random password
	 */
	static generateSecure(length: number = 16): string {
		const lowercase = "abcdefghijklmnopqrstuvwxyz";
		const uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		const numbers = "0123456789";
		const symbols = "!@#$%^&*()_+-=[]{}|;:,.<>?";

		const allChars = lowercase + uppercase + numbers + symbols;

		let password = "";

		// Ensure at least one character from each category
		password += lowercase[Math.floor(Math.random() * lowercase.length)];
		password += uppercase[Math.floor(Math.random() * uppercase.length)];
		password += numbers[Math.floor(Math.random() * numbers.length)];
		password += symbols[Math.floor(Math.random() * symbols.length)];

		// Fill the rest randomly
		for (let i = 4; i < length; i++) {
			password += allChars[Math.floor(Math.random() * allChars.length)];
		}

		// Shuffle the password
		return password
			.split("")
			.sort(() => Math.random() - 0.5)
			.join("");
	}

	/**
	 * Check if password is in common passwords list
	 */
	private static isCommonPassword(password: string): boolean {
		const commonPasswords = [
			"password",
			"123456",
			"123456789",
			"qwerty",
			"abc123",
			"password123",
			"admin",
			"letmein",
			"welcome",
			"monkey",
			"1234567890",
			"dragon",
			"master",
			"login",
			"pass",
			"football",
			"baseball",
			"superman",
			"access",
			"shadow",
			"trustno1",
			"12345678",
			"password1",
			"passw0rd",
			"qwerty123",
			"welcome123",
			"123123",
			"password!",
			"qwerty1",
		];

		return commonPasswords.includes(password.toLowerCase());
	}

	/**
	 * Check for weak patterns in password
	 */
	private static hasWeakPatterns(password: string): boolean {
		// Check for repeated characters (3+ in a row)
		if (/(.)\1{2,}/.test(password)) {
			return true;
		}

		// Check for sequential characters
		const sequential = [
			"abcdefghijklmnopqrstuvwxyz",
			"0123456789",
			"qwertyuiopasdfghjklzxcvbnm",
		];

		for (const seq of sequential) {
			for (let i = 0; i <= seq.length - 3; i++) {
				if (password.toLowerCase().includes(seq.substr(i, 3))) {
					return true;
				}
			}
		}

		return false;
	}

	/**
	 * Generate a secure temporary password for password reset
	 */
	static generateTemporary(): string {
		return PasswordSecurity.generateSecure(12);
	}

	/**
	 * Check if password needs to be rehashed (cost factor changed)
	 */
	static async needsRehash(hash: string): Promise<boolean> {
		// Check if the hash was created with a different cost factor
		// For bcrypt, we can extract the cost from the hash
		try {
			const costMatch = hash.match(/\$2[aby]?\$(\d+)\$/);
			if (!costMatch) return true; // Invalid hash format, needs rehash

			const currentCost = parseInt(costMatch[1], 10);
			return currentCost < 12; // Our target cost is 12
		} catch {
			return true; // If we can't parse, assume it needs rehash
		}
	}
}
