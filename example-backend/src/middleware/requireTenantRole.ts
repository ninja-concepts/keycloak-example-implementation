import type { Request, Response, NextFunction } from 'express';

/**
 * Creates a middleware function that checks if the authenticated user has a required role
 * within the active tenant context.
 * 
 * This middleware MUST run *after* the `tenantContext` middleware has successfully
 * populated `req.tenant`.
 *
 * @param {string | string[]} requiredRole - The role or list of roles to check for.
 * If an array is provided, the user only needs to have one of the roles.
 * @returns An Express middleware function.
 */
export function requireTenantRole(requiredRole: string | string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    // 1. Ensure tenant context exists. If not, it means `tenantContext` middleware
    // did not run or failed, which is a server configuration issue.
    if (!req.tenant) {
      console.error('ProgrammingError: requireTenantRole was called without a valid tenant context on the request. Ensure tenantContext middleware runs first.');
      return res.status(500).json({ message: 'Server configuration error: Could not determine company context.' });
    }

    const { roles: userRoles, id: tenantId } = req.tenant;
    const requiredRoles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];

    // 2. Check if the user's roles for this tenant include any of the required roles.
    const hasRequiredRole = requiredRoles.some(role => userRoles.includes(role));

    if (hasRequiredRole) {
      return next(); // Success: User has the required role in this tenant.
    }

    // 3. If no required role is found, deny access.
    console.warn(`AuthorizationError: User ${req.auth?.sub} denied access to a resource in tenant ${tenantId}. Required roles: [${requiredRoles.join(', ')}], User's roles: [${userRoles.join(', ')}]`);
    return res.status(403).json({ 
        message: `Access denied: This action requires one of the following roles in this company: ${requiredRoles.join(', ')}.`,
        error: 'FORBIDDEN'
    });
  };
} 