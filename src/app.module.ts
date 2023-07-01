import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { JwtModule } from '@nestjs/jwt'
import { UsersModule } from 'src/users/users.module'

@Module({
  imports: [
    UsersModule,
    ConfigModule.forRoot({ isGlobal: true }),
    JwtModule.register({ global: true }),
  ],
})
export class AppModule {}
