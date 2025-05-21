import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  getHello(): string {
    return 'Welcome to the Payment API! Please refer to /api for the Swagger documentation.';
  }
}