import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { EmailService } from './email.service';
import { EmailController } from './email.controller';
import { PrismaService } from '../../prisma.service';

@Module({
  imports: [ConfigModule],
  controllers: [EmailController],
  providers: [EmailService, PrismaService],
  exports: [EmailService],
})
export class EmailModule {}