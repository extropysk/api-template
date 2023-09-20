import { Module } from '@nestjs/common'
import { ConfigModule, ConfigService } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { WinstonModule, utilities as nestWinstonModuleUtilities } from 'nest-winston'
import { UsersModule } from 'src/users/users.module'
import * as winston from 'winston'
import LokiTransport from 'winston-loki'

@Module({
  imports: [
    UsersModule,
    ConfigModule.forRoot({ isGlobal: true }),
    JwtModule.register({ global: true }),
    WinstonModule.forRootAsync({
      useFactory: (configService: ConfigService) => {
        return {
          level: 'info',
          transports: [
            new winston.transports.Console({
              format: winston.format.combine(
                winston.format.timestamp(),
                winston.format.ms(),
                nestWinstonModuleUtilities.format.nestLike(process.env.npm_package_name, {
                  colors: true,
                  prettyPrint: true,
                })
              ),
            }),
            new LokiTransport({
              level: 'error',
              format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
              host: configService.get<string>('LOKI_HOST'),
              json: true,
              basicAuth: configService.get<string>('LOKI_CREDENTIALS'),
              labels: {
                app_name: process.env.npm_package_name,
                app_version: process.env.npm_package_version,
                app_environment: configService.get<string>('NODE_ENV', 'development'),
              },
            }),
          ],
        }
      },
      inject: [ConfigService],
    }),
  ],
})
export class AppModule {}
