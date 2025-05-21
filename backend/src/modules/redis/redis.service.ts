import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private redisClient: Redis;
  private redisEnabled: boolean;
  private readonly logger = new Logger(RedisService.name);

  constructor(private configService: ConfigService) {
    this.redisEnabled = this.configService.get('REDIS_ENABLED') === 'true';
    
    if (this.redisEnabled) {
      try {
        this.redisClient = new Redis({
          host: this.configService.get('REDIS_HOST'),
          port: parseInt(this.configService.get('REDIS_PORT'), 10),
          password: this.configService.get('REDIS_PASSWORD') || undefined,
          db: parseInt(this.configService.get('REDIS_DB'), 10) || 0,
          keyPrefix: this.configService.get('REDIS_KEY_PREFIX'),
          maxRetriesPerRequest: 3,
          enableOfflineQueue: false,
          connectTimeout: 10000,
          retryStrategy: (times) => {
            const delay = Math.min(times * 200, 2000);
            return delay;
          },
        });

        this.redisClient.on('error', (err) => {
          this.logger.error(`Redis error: ${err.message}`);
        });

        this.redisClient.on('connect', () => {
          this.logger.log('Redis connected');
        });

        this.redisClient.on('reconnecting', () => {
          this.logger.log('Redis reconnecting');
        });
      } catch (error) {
        this.logger.error(`Redis initialization error: ${error.message}`);
        this.redisEnabled = false;
      }
    } else {
      this.logger.warn('Redis is disabled. Using memory storage fallback.');
    }
  }
  async onModuleInit() {
    // Test the connection if Redis is enabled
    if (this.redisEnabled && this.redisClient) {
      try {
        await this.redisClient.ping();
        this.logger.log('Redis connection established');
      } catch (error) {
        this.logger.error(`Redis connection failed: ${error.message}`);
        this.redisEnabled = false;
      }
    }
  }

  async onModuleDestroy() {
    if (this.redisEnabled && this.redisClient) {
      await this.redisClient.quit();
    }
  }

  getClient(): Redis {
    if (!this.redisEnabled || !this.redisClient) {
      this.logger.warn('Redis is not available. Operations will be skipped.');
    }
    return this.redisClient;
  }

  async set(key: string, value: any, ttl?: number): Promise<void> {
    if (!this.redisEnabled || !this.redisClient) return;
    
    try {
      const serializedValue = typeof value === 'object' 
        ? JSON.stringify(value) 
        : String(value);
        
      if (ttl) {
        await this.redisClient.set(key, serializedValue, 'EX', ttl);
      } else {
        await this.redisClient.set(key, serializedValue);
      }
    } catch (error) {
      this.logger.error(`Redis set error for key ${key}: ${error.message}`);
    }
  }
  async get(key: string): Promise<any> {
    if (!this.redisEnabled || !this.redisClient) return null;
    
    try {
      const value = await this.redisClient.get(key);
      if (!value) return null;
      
      try {
        return JSON.parse(value);
      } catch {
        return value;
      }
    } catch (error) {
      this.logger.error(`Redis get error for key ${key}: ${error.message}`);
      return null;
    }
  }

  async del(key: string): Promise<void> {
    if (!this.redisEnabled || !this.redisClient) return;
    
    try {
      await this.redisClient.del(key);
    } catch (error) {
      this.logger.error(`Redis del error for key ${key}: ${error.message}`);
    }
  }

  async exists(key: string): Promise<boolean> {
    if (!this.redisEnabled || !this.redisClient) return false;
    
    try {
      const result = await this.redisClient.exists(key);
      return result === 1;
    } catch (error) {
      this.logger.error(`Redis exists error for key ${key}: ${error.message}`);
      return false;
    }
  }

  async setWithExpiry(key: string, value: any, ttl: number): Promise<void> {
    return this.set(key, value, ttl);
  }

  async getKeys(pattern: string): Promise<string[]> {
    if (!this.redisEnabled || !this.redisClient) return [];
    
    try {
      return this.redisClient.keys(pattern);
    } catch (error) {
      this.logger.error(`Redis getKeys error for pattern ${pattern}: ${error.message}`);
      return [];
    }
  }
}
