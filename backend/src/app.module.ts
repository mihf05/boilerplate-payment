import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaService } from './prisma.service';
import { UsersModule } from './modules/users/users.module';
import { AuthModule } from './modules/auth/auth.module';
import { TenantsModule } from './modules/tenants/tenants.module';
import { InvoicesModule } from './modules/invoices/invoices.module';
import { PaymentsModule } from './modules/payments/payments.module';
import { CurrencyModule } from './modules/currency/currency.module';
import { EmailModule } from './modules/email/email.module';
import { SmsModule } from './modules/sms/sms.module';
import { QrcodeModule } from './modules/qrcode/qrcode.module';
import { RetryModule } from './modules/retry/retry.module';
import { WebhookModule } from './modules/webhook/webhook.module';

@Module({
  imports: [
    UsersModule,
    AuthModule,
    TenantsModule,
    InvoicesModule,
    PaymentsModule,
    CurrencyModule,
    EmailModule,
    SmsModule,
    QrcodeModule,
    RetryModule,
    WebhookModule,
  ],
  controllers: [AppController],
  providers: [AppService, PrismaService],
})
export class AppModule {}