import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Req } from '@nestjs/common';
import { ApiBearerAuth, ApiTags, ApiOperation } from '@nestjs/swagger';
import { UsersService } from './users.service';
import { JwtAuthGuard } from '../auth/guards/jwt-auth.guard';
import { RolesGuard } from '../auth/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '@prisma/client';

// DTOs
class UpdateUserDto {
  name?: string;
  email?: string;
  password?: string;
  role?: Role;
}

@ApiTags('users')
@Controller('users')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class UsersController {
  constructor(private readonly usersService: UsersService) {}

  @Get()
  @UseGuards(RolesGuard)
  @Roles(Role.ADMIN)
  @ApiOperation({ summary: 'Get all users (Admin only)' })
  findAll(@Req() req) {
    return this.usersService.findAll(req.user.tenantId);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get a user by ID' })
  findOne(@Param('id') id: string, @Req() req) {
    // Regular users can only access their own data, admins can access any user data
    if (req.user.role !== Role.ADMIN && req.user.id !== id) {
      return this.usersService.findOne(req.user.id);
    }
    return this.usersService.findOne(id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update a user' })
  update(
    @Param('id') id: string,
    @Body() updateUserDto: UpdateUserDto,
    @Req() req,
  ) {
    // Regular users can only update their own data, admins can update any user data
    if (req.user.role !== Role.ADMIN && req.user.id !== id) {
      return this.usersService.update(req.user.id, updateUserDto);
    }
    
    // Only admins can update roles
    if (updateUserDto.role && req.user.role !== Role.ADMIN) {
      delete updateUserDto.role;
    }
    
    return this.usersService.update(id, updateUserDto);
  }

  @Delete(':id')
  @UseGuards(RolesGuard)
  @Roles(Role.ADMIN)
  @ApiOperation({ summary: 'Delete a user (Admin only)' })
  remove(@Param('id') id: string) {
    return this.usersService.remove(id);
  }
}