import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as nodemailer from 'nodemailer';
import { PrismaService } from '../../prisma.service';

@Injectable()
export class EmailService {
  private transporter: nodemailer.Transporter;

  constructor(
    private configService: ConfigService,
    private prisma: PrismaService,
  ) {
    // Initialize nodemailer transporter
    this.transporter = nodemailer.createTransport({
      host: this.configService.get('EMAIL_HOST'),
      port: this.configService.get('EMAIL_PORT'),
      secure: this.configService.get('EMAIL_SECURE') === 'true',
      auth: {
        user: this.configService.get('EMAIL_USER'),
        pass: this.configService.get('EMAIL_PASS'),
      },
    });
  }
  async sendEmail(to: string, subject: string, html: string) {
    try {
      const result = await this.transporter.sendMail({
        from: this.configService.get('EMAIL_FROM') || '"Payment App" <noreply@example.com>',
        to,
        subject,
        html,
      });

      // Log the email to the database
      await this.prisma.emailLog.create({
        data: {
          to,
          subject,
          body: html,
        },
      });

      return result;
    } catch (error) {
      console.error('Error sending email:', error);
      throw error;
    }
  }
  async sendVerificationEmail(to: string, token: string) {
    const baseUrl = this.configService.get('APP_URL') || 'http://localhost:3000';
    const verificationLink = `${baseUrl}/auth/verify?token=${token}`;
    
    const subject = 'Verify Your Email Address';
    const html = `
      <h1>Verify Your Email Address</h1>
      <p>Thank you for registering with our platform. Please click the link below to verify your email address:</p>
      <p><a href="${verificationLink}">Verify Email</a></p>
      <p>If you did not create an account, please ignore this email.</p>
      <p>The link will expire in 24 hours.</p>
    `;

    return this.sendEmail(to, subject, html);
  }
  async sendPasswordResetEmail(to: string, token: string) {
    const baseUrl = this.configService.get('APP_URL') || 'http://localhost:3000';
    const resetLink = `${baseUrl}/auth/reset-password?token=${token}`;
    
    const subject = 'Reset Your Password';
    const html = `
      <h1>Reset Your Password</h1>
      <p>You requested to reset your password. Please click the link below to reset your password:</p>
      <p><a href="${resetLink}">Reset Password</a></p>
      <p>If you did not request a password reset, please ignore this email.</p>
      <p>The link will expire in 1 hour.</p>
    `;

    return this.sendEmail(to, subject, html);
  }
  async sendWelcomeEmail(to: string, name: string) {
    const subject = 'Welcome to Payment App';
    const html = `
      <h1>Welcome to Payment App, ${name}!</h1>
      <p>Thank you for joining our platform. We're excited to have you on board.</p>
      <p>With our app, you can:</p>
      <ul>
        <li>Manage payments and invoices</li>
        <li>Track transactions</li>
        <li>Analyze your financial data</li>
      </ul>
      <p>If you have any questions, please don't hesitate to contact our support team.</p>
    `;

    return this.sendEmail(to, subject, html);
  }
}
