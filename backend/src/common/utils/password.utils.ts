import * as bcrypt from 'bcrypt';

/**
 * Hashes a password using bcrypt
 * @param password - The password to hash
 * @returns The hashed password
 */
export async function hashPassword(password: string): Promise<string> {
  const salt = await bcrypt.genSalt();
  return bcrypt.hash(password, salt);
}

/**
 * Compares a password with a hash
 * @param plainPassword - The plain text password
 * @param hashedPassword - The hashed password
 * @returns Whether the password matches the hash
 */
export async function comparePasswords(
  plainPassword: string,
  hashedPassword: string,
): Promise<boolean> {
  return bcrypt.compare(plainPassword, hashedPassword);
}
