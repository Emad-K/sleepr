import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { UserDocument } from '@app/common';
import { JwtService } from '@nestjs/jwt';
import { TokenPayload } from './interfaces/token-payload.interface';

@Injectable()
export class AuthService {
  constructor(
    private readonly configService: ConfigService,
    private readonly jwtService: JwtService,
  ) {}

  async login(user: UserDocument) {
    const tokenPayload: TokenPayload = {
      userId: user._id.toHexString(),
    };

    this.configService.get('JWT_EXPIRATION');

    const token = this.jwtService.sign(tokenPayload);

    return token;
  }
}
