import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

/* eslint-disable prettier/prettier */
export class AuthDto {
    @IsEmail()
    @IsNotEmpty()
    email: string

    @IsNotEmpty()
    @IsString()
    password: string
}