import {
  CanActivate,
  ExecutionContext,
  Inject,
  Injectable,
  LoggerService,
  UnauthorizedException,
} from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import { JwtService } from '@nestjs/jwt'
import { Request } from 'express'
import { WINSTON_MODULE_NEST_PROVIDER } from 'nest-winston'

@Injectable()
export class JwtGuard implements CanActivate {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
    @Inject(WINSTON_MODULE_NEST_PROVIDER) private readonly logger: LoggerService
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()
    const token = this.extractTokenFromHeader(request)

    if (!token) {
      throw new UnauthorizedException()
    }
    try {
      const payload = await this.jwtService.verifyAsync(token, {
        publicKey: this.configService.get<string>('JWT_PUBLIC_KEY'),
      })

      // 💡 We're assigning the payload to the request object here
      // so that we can access it in our route handlers
      request['user'] = payload
      this.logger.log({ sub: payload.sub, message: 'auth' }, JwtGuard.name)
    } catch {
      throw new UnauthorizedException()
    }

    return true
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? []
    return type === 'Bearer' ? token : undefined
  }
}
