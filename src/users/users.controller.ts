import { Controller, Get } from '@nestjs/common'
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger'
import { Current } from 'src/core/decorators/current.decorator'
import { Jwt } from 'src/core/decorators/jwt.decorator'
import { PayloadDto } from 'src/core/dto/payload.dto'
import { Payload } from 'src/core/interfaces/payload.interface'
import { UsersService } from 'src/users/users.service'

@ApiTags('users')
@Controller('users')
@Jwt()
export class UsersController {
  constructor(private usersService: UsersService) {}

  @ApiOperation({ summary: 'Get current user' })
  @ApiOkResponse({ type: PayloadDto })
  @Get('current')
  getProfile(@Current() current: Payload) {
    return this.usersService.getCurrentUser(current)
  }
}
