import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';

import { UpdateUserDto } from './dto/update-auth.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';

import * as bcryptjs from 'bcryptjs'
import { LoginDto } from './dto/login.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';
import { RegisterUserDto } from './dto';


@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtServices: JwtService
  ){ }


  async create(createUserDto: CreateUserDto):Promise<User> {
    
    try {    
      const {password, ...userData} = createUserDto
      
      //1- Encriptar las contraseñas
      const newUser = new this.userModel({
        password: bcryptjs.hashSync(password, 10),
        ...userData
      })
        
      // 2- Guardar el usuario
       await newUser.save()

       const {password:_, ...user} = newUser.toJSON()

       return user

    } catch (error) {
      if(error.code == 11000){
        throw new BadRequestException(`${createUserDto.email} alredy exists!`)
      }
      throw new BadRequestException(`Error!`)
      
    }


  }

  async register(registerUserDto: RegisterUserDto):Promise<LoginResponse>{

    const user = await this.create(registerUserDto)
    
    return {
      user,
      token : this.getJwtToken({id: user._id})
    }
  }

  async login(loginDto: LoginDto):Promise<LoginResponse>{

  const {email, password} = loginDto;

  const user = await this.userModel.findOne({email})
    
    if(!user){
      throw new UnauthorizedException('Nota valid credentials - email')
    }
    
    if(!bcryptjs.compareSync(password, user.password)){
      
      throw new UnauthorizedException('Nota valid credentials - password')
    }


    const { password:_, ...rest} =user.toJSON()

    return {
      user: rest,
      token:this.getJwtToken({id: user.id})
    }

  }

  findAll() {
    return this.userModel.find()
  }

  async findUserById(id: string){
    const user= await this.userModel.findById(id)
    const {password, ...rest}= user.toJSON()
    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload:JwtPayload){

    
    const token = this.jwtServices.sign(payload);
    return token
  }
}
