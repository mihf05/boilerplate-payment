import { Injectable, CanActivate, ExecutionContext, ForbiddenException } from '@nestjs/common';

@Injectable()
export class TenantGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest();
    const user = request.user;
    const tenantId = request.params.tenantId || request.body.tenantId;

    // If no tenant ID is specified in the request, allow the request
    if (!tenantId) {
      return true;
    }

    // Check if the user belongs to the requested tenant
    if (user.tenantId !== tenantId) {
      throw new ForbiddenException('You are not authorized to access this tenant');
    }

    return true;
  }
}