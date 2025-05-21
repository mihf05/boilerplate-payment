import { Controller, Post, Body, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiTags, ApiOperation } from '@nestjs/swagger';
import { EmailService } from './email.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '@prisma/client';

// DTOs
class SendEmailDto {
  tenantId: string;
  to: string;
  subject: string;
  html: string;
}

@ApiTags('email')
@Controller('email')
export class EmailController {
  constructor(private emailService: EmailService) {}

  @Post('send')
  @ApiBearerAuth()
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles(Role.ADMIN)
  @ApiOperation({ summary: 'Send email' })
  async sendEmail(@Body() sendEmailDto: SendEmailDto) {
    return this.emailService.sendEmail(
      sendEmailDto.tenantId,
      sendEmailDto.to,
      sendEmailDto.subject,
      sendEmailDto.html,
    );
  }
}