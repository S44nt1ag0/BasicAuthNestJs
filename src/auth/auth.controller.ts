import {
  Body,
  Controller,
  Get,
  Post,
  Request,
  UseGuards,
} from '@nestjs/common';
import { SignInDTO, SignUpDTO } from './DTO/auth';
import { AuthService } from './auth.service';
import { AuthGuard } from './auth.guard';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('signup')
  async signup(@Body() body: SignUpDTO) {
    return this.authService.signUp(body);
  }

  @Post('signin')
  async sigin(@Body() body: SignInDTO) {
    return this.authService.signIn(body);
  }

  @UseGuards(AuthGuard)
  @Get('me')
  me(@Request() request) {
    return request.user;
  }
}
