import { Injectable, UnauthorizedException, ConflictException, NotFoundException, BadRequestException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../../prisma.service';
import { EmailService } from '../email/email.service';
import { RedisService } from '../redis/redis.service';
import { Role } from '@prisma/client';

// DTOs
interface SignupDto {
  email: string;
  password: string;
  name: string;
}

interface LoginDto {
  email: string;
  password: string;
}

interface VerifyEmailDto {
  token: string;
}

interface ForgotPasswordDto {
  email: string;
}

interface ResetPasswordDto {
  token: string;
  password: string;
}

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private emailService: EmailService,
    private redisService: RedisService,
  ) {}
  async signup(signupDto: SignupDto) {
    const { email, password, name } = signupDto;

    // Check if user exists
    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      throw new ConflictException('Email already in use');
    }

    // Hash password
    const hashedPassword = await this.hashPassword(password);

    // Create user
    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
      },
    });

    // Generate verification token
    const verificationToken = this.generateEmailVerificationToken(user.id);

    // Store token in Redis
    const tokenKey = `email_verification:${user.id}`;
    await this.redisService.set(
      tokenKey, 
      { verified: false }, 
      parseInt(this.configService.get('jwt.emailVerificationExpiration'))
    );

    // Send verification email
    await this.emailService.sendVerificationEmail(email, verificationToken);

    return {
      message: 'User registered successfully. Please check your email to verify your account.',
    };
  }
  async login(loginDto: LoginDto) {
    const { email, password } = loginDto;

    // Find user
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Verify password
    const isPasswordValid = await this.comparePasswords(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check email verification status
    const isVerified = await this.isEmailVerified(user.id);
    if (!isVerified) {
      throw new UnauthorizedException('Email not verified. Please verify your email to login.');
    }

    // Generate tokens
    const tokens = this.generateTokens(user);

    // Store refresh token in Redis
    const refreshTokenKey = `refresh_token:${user.id}`;
    await this.redisService.set(
      refreshTokenKey, 
      { token: tokens.refreshToken }, 
      parseInt(this.configService.get('jwt.refreshTokenExpiration'))
    );

    return {
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role,
      },
      ...tokens,
    };
  }
  async verifyEmail(verifyEmailDto: VerifyEmailDto) {
    const { token } = verifyEmailDto;

    try {
      // Verify token
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.get('jwt.secret'),
      });

      const userId = decoded.sub;
      if (!userId) {
        throw new BadRequestException('Invalid token');
      }

      // Check if token exists in Redis
      const tokenKey = `email_verification:${userId}`;
      const exists = await this.redisService.exists(tokenKey);

      if (!exists) {
        throw new BadRequestException('Token expired or invalid');
      }

      // Mark email as verified
      await this.redisService.set(
        tokenKey, 
        { verified: true }, 
        parseInt(this.configService.get('jwt.emailVerificationExpiration'))
      );

      // Get user
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (user) {
        // Send welcome email
        await this.emailService.sendWelcomeEmail(user.email, user.name);
      }

      return { message: 'Email verified successfully' };
    } catch (error) {
      throw new BadRequestException('Invalid or expired token');
    }
  }
  async forgotPassword(forgotPasswordDto: ForgotPasswordDto) {
    const { email } = forgotPasswordDto;

    // Find user
    const user = await this.prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Generate password reset token
    const resetToken = this.generatePasswordResetToken(user.id);

    // Store token in Redis
    const tokenKey = `password_reset:${user.id}`;
    await this.redisService.set(
      tokenKey, 
      { token: resetToken }, 
      parseInt(this.configService.get('jwt.passwordResetExpiration'))
    );

    // Send password reset email
    await this.emailService.sendPasswordResetEmail(email, resetToken);

    return {
      message: 'Password reset instructions sent to your email',
    };
  }

  async resetPassword(resetPasswordDto: ResetPasswordDto) {
    const { token, password } = resetPasswordDto;

    try {
      // Verify token
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.get('jwt.secret'),
      });

      const userId = decoded.sub;
      if (!userId) {
        throw new BadRequestException('Invalid token');
      }

      // Check if token exists in Redis
      const tokenKey = `password_reset:${userId}`;
      const exists = await this.redisService.exists(tokenKey);

      if (!exists) {
        throw new BadRequestException('Token expired or invalid');
      }

      // Hash new password
      const hashedPassword = await this.hashPassword(password);

      // Update user password
      await this.prisma.user.update({
        where: { id: userId },
        data: { password: hashedPassword },
      });

      // Delete token from Redis
      await this.redisService.del(tokenKey);

      return { message: 'Password reset successfully' };
    } catch (error) {
      throw new BadRequestException('Invalid or expired token');
    }
  }

  async logout(userId: string) {
    // Delete refresh token from Redis
    const refreshTokenKey = `refresh_token:${userId}`;
    await this.redisService.del(refreshTokenKey);

    return { message: 'Logged out successfully' };
  }

  async refreshToken(token: string) {
    try {
      // Verify token
      const decoded = this.jwtService.verify(token, {
        secret: this.configService.get('jwt.secret'),
      });

      const userId = decoded.sub;
      if (!userId) {
        throw new UnauthorizedException('Invalid token');
      }

      // Check if token exists in Redis
      const refreshTokenKey = `refresh_token:${userId}`;
      const storedToken = await this.redisService.get(refreshTokenKey);

      if (!storedToken || storedToken.token !== token) {
        throw new UnauthorizedException('Invalid token');
      }

      // Get user
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Generate new tokens
      const tokens = this.generateTokens(user);

      // Store new refresh token in Redis
      await this.redisService.set(
        refreshTokenKey, 
        { token: tokens.refreshToken }, 
        parseInt(this.configService.get('jwt.refreshTokenExpiration'))
      );

      return tokens;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
  async validateUser(userId: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
    };
  }

  async isEmailVerified(userId: string): Promise<boolean> {
    const tokenKey = `email_verification:${userId}`;
    const verification = await this.redisService.get(tokenKey);

    // For development/testing purposes, consider all emails verified if no Redis record
    if (!verification) {
      return true;
    }

    return verification.verified;
  }

  // Helper methods
  private async hashPassword(password: string): Promise<string> {
    const salt = await bcrypt.genSalt();
    return bcrypt.hash(password, salt);
  }

  private async comparePasswords(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(plainPassword, hashedPassword);
  }

  private generateTokens(user: any) {
    const payload = { email: user.email, sub: user.id, role: user.role };

    const accessToken = this.jwtService.sign(payload, {
      secret: this.configService.get('jwt.secret'),
      expiresIn: this.configService.get('jwt.accessTokenExpiration'),
    });

    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get('jwt.secret'),
      expiresIn: this.configService.get('jwt.refreshTokenExpiration'),
    });

    return {
      accessToken,
      refreshToken,
    };
  }

  private generateEmailVerificationToken(userId: string): string {
    const payload = { sub: userId };
    return this.jwtService.sign(payload, {
      secret: this.configService.get('jwt.secret'),
      expiresIn: this.configService.get('jwt.emailVerificationExpiration'),
    });
  }

  private generatePasswordResetToken(userId: string): string {
    const payload = { sub: userId };
    return this.jwtService.sign(payload, {
      secret: this.configService.get('jwt.secret'),
      expiresIn: this.configService.get('jwt.passwordResetExpiration'),
    });
  }
}
