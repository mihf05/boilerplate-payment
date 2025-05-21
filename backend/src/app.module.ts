import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { ScheduleModule } from '@nestjs/schedule';
import { ThrottlerModule } from '@nestjs/throttler';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { PrismaService } from './prisma.service';

// Modules
import { AuthModule } from './modules/auth/auth.module';
import { EmailModule } from './modules/email/email.module';
import { RedisModule } from './modules/redis/redis.module';
import { UsersModule } from './modules/users/users.module';

// Config
import jwtConfig from './config/jwt.config';
import redisConfig from './config/redis.config';
import databaseConfig from './config/database.config';
import paymentConfig from './config/payment.config';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [jwtConfig, redisConfig, databaseConfig, paymentConfig],
    }),
    ThrottlerModule.forRoot([{
      ttl: 60,
      limit: 10,
    }]),
    ScheduleModule.forRoot(),
    AuthModule,
    EmailModule,
    RedisModule,
    UsersModule,
  ],
  controllers: [AppController],
  providers: [AppService, PrismaService],
})
export class AppModule {}