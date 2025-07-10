import { expressjwt } from "express-jwt";
import type { GetVerificationKey } from "express-jwt";
import { expressJwtSecret } from "jwks-rsa";
import { env } from "../config/env";
import type { NextFunction, Request, Response } from "express";

// Define the structure of the JWT payload we expect from Keycloak
interface DecodedJwt {
   // We only care about the user's identity (sub) and their tenant memberships (groups)
   sub: string;
   groups?: string[]; // e.g., ['/company-a', '/company-b']

   // Standard JWT claims
   exp: number;
   iat: number;
   iss: string;
   aud: string | string[];
   azp: string;

   // Other potential claims from Keycloak - we don't use them for authorization
   auth_time?: number;
   jti: string;
   typ: string;
   session_state?: string;
   acr?: string;
   'allowed-origins': string[];
   scope?: string;
   sid?: string;
   email_verified?: boolean;
   name?: string;
   preferred_username?: string;
   given_name?: string;
   family_name?: string;
   email?: string;
}

// Extend Express Request type
// This allows us to safely access `req.auth` after the `jwtCheck` middleware runs.
declare global {
   namespace Express {
      export interface Request {
         auth?: DecodedJwt;
      }
   }
}

const keycloakIssuer = `${env.KEYCLOAK_URL}/realms/${env.KEYCLOAK_REALM}`;

// JWT validation middleware
// This middleware's only job is AUTHENTICATION: it verifies the token's signature
// and attaches the decoded payload to `req.auth`. It does not handle AUTHORIZATION.
export const jwtCheck = expressjwt({
   secret: expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `${keycloakIssuer}/protocol/openid-connect/certs`,
   }) as GetVerificationKey,
   audience: [env.KEYCLOAK_CLIENT_ID, "account"],
   issuer: keycloakIssuer,
   algorithms: ["RS256"],
});


// Error handler for express-jwt errors.
// This should be registered in the main app file AFTER all routes.
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