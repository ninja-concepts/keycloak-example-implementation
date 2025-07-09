import { expressjwt } from "express-jwt";
import type { GetVerificationKey } from "express-jwt";
import { expressJwtSecret } from "jwks-rsa";
import { env } from "../config/env";
import type { NextFunction, Request, Response } from "express";

// Define the structure of the JWT payload we expect from Keycloak
interface DecodedJwt {
   exp: number;
   iat: number;
   auth_time?: number;
   jti: string;
   iss: string;
   aud: string | string[];
   sub: string;
   typ: string;
   azp: string;
   session_state?: string;
   acr?: string;
   'allowed-origins': string[];
   realm_access?: {
      roles?: string[];
   };
   resource_access?: {
      [clientId: string]: {
         roles?: string[];
      };
   };
   scope?: string;
   sid?: string;
   email_verified?: boolean;
   name?: string;
   preferred_username?: string;
   given_name?: string;
   family_name?: string;
   email?: string;
   // Add any other custom claims you expect
}

// Extend Express Request type
declare global {
   namespace Express {
      export interface Request {
         auth?: DecodedJwt;
      }
   }
}

const keycloakIssuer = `${env.KEYCLOAK_URL}/realms/${env.KEYCLOAK_REALM}`;

// JWT validation middleware
export const jwtCheck = expressjwt({
   secret: expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `${keycloakIssuer}/protocol/openid-connect/certs`,
   }) as GetVerificationKey,
   audience: [env.KEYCLOAK_CLIENT_ID, "account"], // Temporarily accept "account" audience
   issuer: keycloakIssuer,
   algorithms: ["RS256"],
   // credentialsRequired: false, // Set to false if you want to allow access to routes even if no token is provided.
   // req.auth will be undefined in such cases.
   // For more granular control, apply this middleware selectively or use .unless()
});

export function getRolesFromToken(decodedToken: DecodedJwt | undefined): string[] {
   if (!decodedToken) {
      return [];
   }
   // Prioritize resource_access roles for the specific client ID, then realm_access roles.
   // Adjust env.KEYCLOAK_CLIENT_ID if a different client ID's roles are needed here.
   const resourceRoles = decodedToken.resource_access?.[env.KEYCLOAK_CLIENT_ID]?.roles || [];
   const realmRoles = decodedToken.realm_access?.roles || [];

   // Using a Set to ensure uniqueness if roles overlap (unlikely for distinct resource/realm roles)
   return Array.from(new Set([...resourceRoles, ...realmRoles]));
}

export function requireAdmin(req: Request, res: Response, next: NextFunction): void {
   if (!req.auth) {
      res.status(401).json({ message: "Authentication required", error: "UNAUTHORIZED" });
      return;
   }
   const roles = getRolesFromToken(req.auth);
   if (roles.includes("admin")) {
      next();
   } else {
      console.warn('Admin access denied:', { userId: req.auth.sub, roles, requiredRole: "admin" });
      res.status(403).json({
         message: "Access denied: Administrator privileges required",
         error: "FORBIDDEN"
      });
   }
}

export function requireRole(role: string) {
   return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.auth) {
         res.status(401).json({ message: "Authentication required", error: "UNAUTHORIZED" });
         return;
      }
      const userRoles = getRolesFromToken(req.auth);
      if (userRoles.includes(role)) {
         next();
      } else {
         console.warn('Role access denied:', { userId: req.auth.sub, roles: userRoles, requiredRole: role });
         res.status(403).json({
            message: `Access denied: '${role}' role required`,
            error: "FORBIDDEN"
         });
      }
   };
}

export function requireAnyRole(roles: string[]) {
   return (req: Request, res: Response, next: NextFunction): void => {
      if (!req.auth) {
         res.status(401).json({ message: "Authentication required", error: "UNAUTHORIZED" });
         return;
      }
      const userRoles = getRolesFromToken(req.auth);
      const hasRequiredRole = roles.some(role => userRoles.includes(role));

      if (hasRequiredRole) {
         next();
      } else {
         console.warn('Any role access denied:', { userId: req.auth.sub, roles: userRoles, requiredRoles: roles });
         res.status(403).json({
            message: `Access denied: One of the following roles required: ${roles.join(', ')}`,
            error: "FORBIDDEN"
         });
      }
   };
}

// Error handler for express-jwt errors.
// This should be registered in app.ts AFTER routes and AFTER jwtCheck middleware.
export function handleJwtError(err: any, req: Request, res: Response, next: NextFunction) {
   if (err.name === 'UnauthorizedError') {
      console.warn('JWT UnauthorizedError:', { error: err.message, path: req.path, code: err.code });
      let message = "Access token is invalid or expired.";
      if (err.code === 'credentials_required') {
         message = "Access token is missing.";
      } else if (err.code === 'invalid_token') {
         message = "Access token is invalid.";
      } else if (err.code === 'revoked_token') {
         message = "Access token has been revoked.";
      }

      res.status(401).json({ message, error: "UNAUTHORIZED", code: err.code });
   } else {
      next(err);
   }
} 