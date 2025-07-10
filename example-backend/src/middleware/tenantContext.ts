import type { Request, Response, NextFunction } from 'express';

// Extend Express Request type to include our custom tenant context.
// This allows subsequent middleware and route handlers to access tenant-specific
// user permissions in a type-safe way.
declare global {
   namespace Express {
      export interface Request {
         tenant?: {
            id: string; // The ID of the company/tenant, e.g., "company-a"
            roles: string[]; // User's roles specific to this tenant, e.g., ["admin"]
            products: string[]; // Products the user can access in this tenant
         };
      }
   }
}

// --- MOCK DATABASE ---
// In a real-world application, this data would come from your persistent database
// (e.g., PostgreSQL, MongoDB). It would be managed by an admin service where
// company administrators can assign roles and product access to their users.
const userPermissionsDb: Record<string, Record<string, { roles: string[], products: string[] }>> = {};

// --- END MOCK DATABASE ---


/**
 * Middleware to establish tenant context for an incoming request.
 * It must run *after* the `jwtCheck` middleware.
 * 
 * It performs three critical functions:
 * 1. Reads the target tenant ID from the 'X-Tenant-ID' header.
 * 2. Verifies that the authenticated user (from `req.auth`) is a member of that
 *    tenant by checking the `groups` claim in their JWT.
 * 3. Fetches the user's specific permissions (roles, product access) for that
 *    tenant from the application's database.
 * 4. Attaches this context to `req.tenant` for use in downstream authorization checks.
 */
export async function tenantContext(req: Request, res: Response, next: NextFunction) {
  // The 'X-Tenant-ID' header is sent by the frontend to specify which
  // company's data the user is trying to operate on.
  const tenantId = req.headers['x-tenant-id'] as string;
  const userId = req.auth?.sub;
  
  // The `groups` claim is added to the JWT by our custom Keycloak mapper.
  // It contains the list of tenants the user belongs to. e.g., ['/company-a', '/company-b']
  const userGroups = req.auth?.groups || [];

  console.log('userGroups', req.auth);

  if (!userId) {
    // This should theoretically not be reached if `jwtCheck` is applied correctly.
    return res.status(401).json({ message: 'Authentication required: User ID missing from token.' });
  }
  
  // --- DYNAMIC MOCK DATA ---
  // For demonstration purposes, we dynamically create permissions for the current user.
  // This makes the example work for anyone who logs in.
  userPermissionsDb[userId] = {
    'company-a': { roles: ['admin', 'user'], products: ['product1', 'product2'] },
    'company-b': { roles: ['user'], products: ['product2'] },
  };
  // --- END DYNAMIC MOCK DATA ---

  if (!tenantId) {
    return res.status(400).json({ message: 'A company context is required. Please provide the company ID in the X-Tenant-ID header.' });
  }

  // 1. Verify tenant membership.
  // The group path from Keycloak typically includes a leading slash, so we match it.
  if (!userGroups.includes(`/${tenantId}`)) {
     console.warn(`AuthorizationError: User ${userId} attempted to access tenant '${tenantId}' but is not a member. User's groups: [${userGroups.join(', ')}]`);
     return res.status(403).json({ message: `Access denied: You are not a member of the company '${tenantId}'.` });
  }
  
  // 2. Fetch the user's specific permissions for this tenant from our application database.
  const permissions = userPermissionsDb[userId]?.[tenantId];

  // This is a crucial check. A user might be in the Keycloak group but not yet
  // provisioned with specific roles in the application's database.
  if (!permissions) {
      console.warn(`AuthorizationError: User ${userId} is a member of tenant '${tenantId}' but has no permissions defined.`);
      return res.status(403).json({ message: `Access denied: You have not been assigned a role within this company.` });
  }

  // 3. Attach the successful context to the request object.
  req.tenant = {
    id: tenantId,
    roles: permissions.roles,
    products: permissions.products,
  };

  next();
} 