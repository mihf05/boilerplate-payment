import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private redisClient: Redis;

  constructor(private configService: ConfigService) {
    this.redisClient = new Redis({
      host: this.configService.get('redis.host'),
      port: this.configService.get('redis.port'),
      password: this.configService.get('redis.password') || undefined,
      db: this.configService.get('redis.db'),
      keyPrefix: this.configService.get('redis.keyPrefix'),
    });
  }

  async onModuleInit() {
    // Test the connection
    try {
      await this.redisClient.ping();
      console.log('Redis connection established');
    } catch (error) {
      console.error('Redis connection failed:', error);
    }
  }

  async onModuleDestroy() {
    await this.redisClient.quit();
  }

  getClient(): Redis {
    return this.redisClient;
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    const serializedValue = typeof value === 'object' 
      ? JSON.stringify(value) 
      : String(value);
      
    if (ttl) {
      await this.redisClient.set(key, serializedValue, 'EX', ttl);
    } else {
      await this.redisClient.set(key, serializedValue);
    }
  }

  async get(key: string): Promise<any> {
    const value = await this.redisClient.get(key);
    if (!value) return null;
    
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }

  async del(key: string): Promise<void> {
    await this.redisClient.del(key);
  }

  async exists(key: string): Promise<boolean> {
    const result = await this.redisClient.exists(key);
    return result === 1;
  }

  async setWithExpiry(key: string, value: any, ttl: number): Promise<void> {
    return this.set(key, value, ttl);
  }

  async getKeys(pattern: string): Promise<string[]> {
    return this.redisClient.keys(pattern);
  }
}
