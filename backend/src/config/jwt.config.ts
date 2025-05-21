import { registerAs } from '@nestjs/config';

export default registerAs('jwt', () => ({
  secret: process.env.JWT_SECRET || 'super-secret-key',
  accessTokenExpiration: process.env.JWT_ACCESS_EXPIRATION || '15m',
  refreshTokenExpiration: process.env.JWT_REFRESH_EXPIRATION || '7d',
  emailVerificationExpiration: process.env.JWT_EMAIL_VERIFICATION_EXPIRATION || '24h',
  passwordResetExpiration: process.env.JWT_PASSWORD_RESET_EXPIRATION || '1h',
}));