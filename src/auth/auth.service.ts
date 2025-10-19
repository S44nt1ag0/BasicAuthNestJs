import * as bcrypt from 'bcrypt';
import { Injectable, UnauthorizedException } from '@nestjs/common';
import { SignInDTO, SignUpDTO } from './DTO/auth';
import { PrismaService } from 'src/prisma/prisma.service';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  async signUp(data: SignUpDTO) {
    const userExist = await this.prismaService.user.findUnique({
      where: {
        email: data.email,
      },
    });

    if (userExist) {
      throw new UnauthorizedException('User already exist.');
    }

    const hashedPassword = await bcrypt.hash(data.password, 10);

    const createUser = await this.prismaService.user.create({
      data: {
        ...data,
        password: hashedPassword,
      },
    });

    return {
      id: createUser.id,
      email: createUser.email,
      name: createUser.name,
    };
  }
  async signIn(data: SignInDTO) {
    const user: any = await this.prismaService.user.findUnique({
      where: {
        email: data.email,
      },
    });

    if (!user) {
      throw new UnauthorizedException('Invalid credentials.');
    }

    const passwordMatch = await bcrypt.compare(data.password, user.password);

    if (!passwordMatch) {
      throw new UnauthorizedException('Invalid credentials.');
    }

    const acess_token = await this.jwtService.signAsync({
      id: user.id,
      email: user.email,
      name: user.name,
    });

    return { acess_token };
  }
}
