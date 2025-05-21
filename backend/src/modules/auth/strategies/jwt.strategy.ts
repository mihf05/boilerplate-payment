import { ExtractJwt, Strategy } from 'passport-jwt';
import { PassportStrategy } from '@nestjs/passport';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AuthService } from '../auth.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private configService: ConfigService,
    private authService: AuthService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: configService.get('jwt.secret'),
    });
  }

  async validate(payload: any) {
    // The payload contains the data we included when creating the token
    // Typically: { email: user.email, sub: user.id, role: user.role }
    try {
      const user = await this.authService.validateUser(payload.sub);
      return user;
    } catch (error) {
      throw new UnauthorizedException('Invalid token');
    }
  }
}
