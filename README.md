# Keycloak Authentication Implementation Guide

Our architecture embraces a hybrid security model that separates broad identity management from fine-grained application permissions. We use Keycloak exclusively for its core strengths: authenticating users and assigning a small, consistent set of universal roles (e.g., `admin`, `manager`, `user`) that define a person's general function within the organization. All specific, resource-level authorization—such as determining if a user can edit a particular project or view a specific document—is handled within the application itself. This philosophy prevents "role explosion" in Keycloak, keeping user management simple and scalable, while empowering each application to enforce its own detailed access control logic, ensuring that security is both robust and context-aware.

## Quick Start

This guide shows you exactly how to implement Keycloak authentication in your React + Express.js projects using **TypeScript** (recommended). Follow these steps to get authentication working.

> **Note**: Always use TypeScript for better type safety and developer experience. All examples below are in TypeScript.

## 🚀 Frontend Setup (React + TypeScript)

### Step 1: Install Dependencies

```bash
npm install keycloak-js
npm install -D @types/keycloak-js
```

### Step 2: Create Keycloak Configuration

Create `src/lib/keycloak.ts`:

```typescript
import Keycloak from 'keycloak-js';

const keycloakConfig = {
   url: import.meta.env.VITE_KEYCLOAK_URL!, // Vite uses import.meta.env
   realm: import.meta.env.VITE_KEYCLOAK_REALM!,
   clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID!
};

const keycloak = new Keycloak(keycloakConfig);

/**
 * Because React Strict-Mode (development) intentionally mounts components twice and
 * because multiple places in the codebase may try to call `initKeycloak`, we need
 * to guarantee that `keycloak.init` is executed **only once**.  Invoking it again
 * throws `Error: A 'Keycloak' instance can only be initialized once.`  We solve
 * this by memoising the initialisation promise.
 */
let initPromise: Promise<Keycloak> | null = null;

/**
 * Initializes Keycloak instance and makes it available globally.
 *
 * @param {() => void} onAuthenticatedCallback - Callback function to execute after successful authentication.
 * @returns {Promise<Keycloak>} A promise that resolves to the Keycloak instance.
 */
export const initKeycloak = (onAuthenticatedCallback: (kc: Keycloak) => void): Promise<Keycloak> => {
   // If initialisation already in progress or finished, just hook into that
   if (initPromise) {
      initPromise.then((kc) => {
         if (kc.authenticated) {
            // Fire callback for late subscribers that still care about auth state
            onAuthenticatedCallback(kc)
         }
      })
      return initPromise
   }

   initPromise = new Promise((resolve, reject) => {
      console.log('Keycloak: Attempting init with onLoad: login-required and checkLoginIframe: false');
      keycloak.init({
         onLoad: 'login-required',
         pkceMethod: 'S256', // Recommended for public clients
         checkLoginIframe: false, // Explicitly disable session status iframe
      })
         .then((authenticated) => {
            console.log(`Keycloak: Init completed. Authenticated: ${authenticated}`);
            if (authenticated) {
               console.log('Keycloak: User is authenticated');
               onAuthenticatedCallback(keycloak);
               resolve(keycloak);
            } else {
               console.warn('Keycloak: User is not authenticated after init with login-required.');
               // For login-required, if not authenticated, Keycloak should have redirected.
               // If we reach here without authentication, it might mean the redirect didn't happen or was blocked.
               resolve(keycloak); // Still resolve, AuthContext will handle state based on isAuthenticated
            }

            // Token refresh mechanism - only set up if authenticated
            if (authenticated) {
               setInterval(() => {
                  keycloak.updateToken(70).then((refreshed) => {
                     if (refreshed) {
                        console.log('Keycloak: Token refreshed');
                     } else {
                        if (keycloak.tokenParsed && typeof keycloak.tokenParsed.exp === 'number' && typeof keycloak.timeSkew !== 'undefined') {
                           console.log('Keycloak: Token not refreshed, valid for ' + Math.round(keycloak.tokenParsed.exp + keycloak.timeSkew - new Date().getTime() / 1000) + ' seconds');
                        } else {
                           console.log('Keycloak: Token not refreshed, unable to determine validity (tokenParsed or exp missing, or timeSkew undefined).');
                        }
                     }
                  }).catch(() => {
                     console.error('Keycloak: Failed to refresh token');
                  });
               }, 60000); // Refresh every 60 seconds
            }
         })
         .catch((error) => {
            console.error('Keycloak: Initialization Failed during init()', error);
            // Allow subsequent attempts if this one failed
            initPromise = null;
            reject(error);
         });
   });

   return initPromise;
};

export default keycloak;
```

### Step 3: Copy the AuthContext Hook

Create `src/contexts/AuthContext.tsx` and copy this code exactly:

```typescript
import { createContext, useContext, useState, useEffect, ReactNode, useCallback, useRef } from 'react'
import Keycloak from 'keycloak-js'
import { initKeycloak } from '../lib/keycloak'

interface User {
   id?: string
   username?: string
   email?: string
   name?: string
   firstName?: string
   lastName?: string
   roles?: string[]
   emailVerified?: boolean
}

interface AuthContextType {
   keycloak: Keycloak | null
   user: User | null
   loading: boolean
   isAuthenticated: boolean
   signIn: () => void
   signOut: () => void
   getToken: () => Promise<string | undefined>
   hasRole: (role: string) => boolean
}

interface AuthProviderProps {
   children: ReactNode
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: AuthProviderProps) {
   const [keycloakInstance, setKeycloakInstance] = useState<Keycloak | null>(null)
   const [user, setUser] = useState<User | null>(null)
   const [loading, setLoading] = useState<boolean>(true)

   const hasRunRef = useRef(false)

   const parseUser = useCallback(async (kc: Keycloak) => {
      if (kc.tokenParsed) {
         const profile: User = {
            id: kc.tokenParsed.sub,
            username: kc.tokenParsed.preferred_username,
            email: kc.tokenParsed.email,
            name: kc.tokenParsed.name,
            firstName: kc.tokenParsed.given_name,
            lastName: kc.tokenParsed.family_name,
            emailVerified: kc.tokenParsed.email_verified,
            roles: kc.tokenParsed.realm_access?.roles || [],
         }
         setUser(profile)
         console.log('AuthContext: User parsed', profile)
      } else {
         setUser(null)
         console.log('AuthContext: Token not parsed, user set to null')
      }
   }, [])

   useEffect(() => {
      // Prevent double-initialisation in React Strict Mode (dev) or rerenders
      if (hasRunRef.current) return
      hasRunRef.current = true

      const initialize = async () => {
         console.log('AuthContext: Starting Keycloak initialization...')
         try {
            const kc = await initKeycloak((kcInstance) => {
               console.log('AuthContext: initKeycloak onAuthenticatedCallback triggered.')
               setKeycloakInstance(kcInstance)
               if (kcInstance.authenticated) {
                  parseUser(kcInstance)
               }
            })
            console.log(`AuthContext: Keycloak instance initialized. kc.authenticated: ${kc.authenticated}`)
            setKeycloakInstance(kc)
            if (kc.authenticated) {
               await parseUser(kc)
            } else {
               console.log('AuthContext: Keycloak initialized but user is not authenticated (onLoad: login-required). User should have been redirected to Keycloak login.')
            }
         } catch (error) {
            console.error("AuthContext: Keycloak initialization error in AuthContext:", error)
            setUser(null)
         } finally {
            setLoading(false)
            console.log('AuthContext: Keycloak initialization attempt finished. Loading set to false.')
         }
      }
      initialize()
   }, [parseUser])

   useEffect(() => {
      if (keycloakInstance) {
         keycloakInstance.onAuthSuccess = async () => {
            console.log('AuthContext: onAuthSuccess event triggered.')
            await parseUser(keycloakInstance)
            setLoading(false)
         }
         keycloakInstance.onAuthError = (errorData) => {
            console.error('AuthContext: onAuthError', errorData)
            setUser(null)
            setLoading(false)
         }
         keycloakInstance.onAuthRefreshSuccess = async () => {
            console.log('AuthContext: onAuthRefreshSuccess')
            await parseUser(keycloakInstance)
         }
         keycloakInstance.onAuthRefreshError = () => {
            console.error('AuthContext: onAuthRefreshError')
            setUser(null)
         }
         keycloakInstance.onAuthLogout = () => {
            console.log('AuthContext: onAuthLogout')
            setUser(null)
         }
         keycloakInstance.onTokenExpired = () => {
            console.warn('AuthContext: onTokenExpired')
            keycloakInstance.updateToken(30).catch(() => {
               console.error('AuthContext: Failed to refresh token after expiry, logging out.')
               setUser(null)
            })
         }
      }
   }, [keycloakInstance, parseUser])

   const signIn = useCallback(() => {
      if (keycloakInstance) {
         console.log('AuthContext: signIn called. Redirecting to Keycloak with redirectUri: ' + window.location.origin + '/')
         keycloakInstance.login({ redirectUri: window.location.origin + '/' })
      }
   }, [keycloakInstance])

   const signOut = useCallback(() => {
      if (keycloakInstance) {
         console.log('AuthContext: signOut called. Redirecting to Keycloak logout.')
         keycloakInstance.logout({ redirectUri: window.location.origin + '/login' })
      }
   }, [keycloakInstance])

   const getToken = useCallback(async (): Promise<string | undefined> => {
      if (keycloakInstance && keycloakInstance.token) {
         try {
            await keycloakInstance.updateToken(5)
            return keycloakInstance.token
         } catch (error) {
            console.error('AuthContext: Failed to refresh token in getToken', error)
            return undefined
         }
      }
      return undefined
   }, [keycloakInstance])

   const hasRole = useCallback((role: string): boolean => {
      if (!keycloakInstance || !keycloakInstance.authenticated || !user || !user.roles) {
         return false
      }
      return user.roles.includes(role)
   }, [keycloakInstance, user])

   return (
      <AuthContext.Provider value={{
         keycloak: keycloakInstance,
         user,
         loading,
         isAuthenticated: !!keycloakInstance?.authenticated,
         signIn,
         signOut,
         getToken,
         hasRole
      }}>
         {children}
      </AuthContext.Provider>
   )
}

export const useAuth = (): AuthContextType => {
   const context = useContext(AuthContext)
   if (!context) {
      throw new Error('useAuth must be used within AuthProvider')
   }
   return context
}
```

### Step 4: Wrap Your App

In your `src/App.tsx`:

```tsx
import { AuthProvider } from './contexts/AuthContext'

function App() {
  return (
    <AuthProvider>
      {/* Your existing app components */}
      <YourAppComponents />
    </AuthProvider>
  )
}

export default App
```

### Step 5: Environment Variables

Add to your `.env`:

```env
VITE_KEYCLOAK_URL=https://your-keycloak-server.com
VITE_KEYCLOAK_REALM=your-realm-name
VITE_KEYCLOAK_CLIENT_ID=your-client-id
```

### Step 6: Use in Components

```tsx
import { useAuth } from '../contexts/AuthContext'

function MyComponent() {
  const { user, isAuthenticated, signIn, signOut, hasRole, loading } = useAuth()
  
  if (loading) return <div>Loading...</div>
  
  if (!isAuthenticated) {
    return <button onClick={signIn}>Sign In</button>
  }
  
  return (
    <div>
      <h1>Welcome, {user?.name}!</h1>
      <p>Email: {user?.email}</p>
      
      {hasRole('admin') && (
        <button>Admin Panel</button>
      )}
      
      <button onClick={signOut}>Sign Out</button>
    </div>
  )
}
```

### Step 7: Making API Calls

Always include the token in your API calls:

```tsx
import { useAuth } from '../contexts/AuthContext'

function useApiCall() {
  const { getToken } = useAuth()

  const fetchData = async <T>(endpoint: string): Promise<T> => {
    const token = await getToken()
    
    const response = await fetch(endpoint, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      }
    })
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`)
    }
    
    return response.json()
  }

  return { fetchData }
}

// Usage in component
function DataComponent() {
  const { fetchData } = useApiCall()
  const [data, setData] = useState<any>(null)

  useEffect(() => {
    fetchData('/api/some-endpoint')
      .then(setData)
      .catch(console.error)
  }, [])

  return <div>{JSON.stringify(data)}</div>
}
```

## 🔧 Backend Setup (Express.js + TypeScript)

### Step 1: Install Dependencies

```bash
npm install express express-jwt jwks-rsa
npm install -D @types/express @types/node typescript ts-node
```

### Step 2: Copy the Auth Middleware

Create `src/middleware/auth.ts` and copy this code exactly:

```typescript
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

function getRolesFromToken(decodedToken: DecodedJwt | undefined): string[] {
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
```

### Step 3: Create Environment Config

Create `src/config/env.ts`:

```typescript
export const env = {
  KEYCLOAK_URL: process.env.KEYCLOAK_URL!,
  KEYCLOAK_REALM: process.env.KEYCLOAK_REALM!,
  KEYCLOAK_CLIENT_ID: process.env.KEYCLOAK_CLIENT_ID!,
  // Add other env vars as needed
}

// Validate required environment variables
const requiredEnvVars = ['KEYCLOAK_URL', 'KEYCLOAK_REALM', 'KEYCLOAK_CLIENT_ID']
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`)
  }
}
```

### Step 4: Environment Variables

Add to your `.env`:

```env
KEYCLOAK_URL=https://your-keycloak-server.com
KEYCLOAK_REALM=your-realm-name
KEYCLOAK_CLIENT_ID=your-client-id
```

### Step 5: Apply Middleware to Your Routes

```typescript
import express from 'express'
import { jwtCheck, requireAdmin, requireRole, requireAnyRole, handleJwtError } from './middleware/auth'

const app = express()

// Apply JWT validation to all API routes
app.use('/api', jwtCheck)

// Public route (no auth needed)
app.get('/api/public', (req: express.Request, res: express.Response) => {
  res.json({ message: 'Anyone can access this' })
})

// Protected route (just need to be logged in)
app.get('/api/protected', (req: express.Request, res: express.Response) => {
  res.json({ 
    message: 'You are logged in',
    userId: req.auth?.sub,
    username: req.auth?.preferred_username
  })
})

// Admin only
app.get('/api/admin-only', requireAdmin, (req: express.Request, res: express.Response) => {
  res.json({ message: 'Admin access required' })
})

// Specific role required
app.get('/api/manager-only', requireRole('manager'), (req: express.Request, res: express.Response) => {
  res.json({ message: 'Manager role required' })
})

// Multiple roles accepted
app.get('/api/staff-area', requireAnyRole(['staff', 'manager', 'admin']), (req: express.Request, res: express.Response) => {
  res.json({ message: 'Staff, manager, or admin can access' })
})

// IMPORTANT: Add error handler AFTER all routes
app.use(handleJwtError)

export default app
```

### Step 6: Access User Info in Routes

```typescript
app.get('/api/user-info', (req: express.Request, res: express.Response) => {
  const user = {
    id: req.auth?.sub,
    username: req.auth?.preferred_username,
    email: req.auth?.email,
    name: req.auth?.name,
    roles: [
      ...(req.auth?.realm_access?.roles || []),
      ...(req.auth?.resource_access?.[process.env.KEYCLOAK_CLIENT_ID!]?.roles || [])
    ]
  }
  
  res.json(user)
})
```

## 🔐 Common Patterns

### Protect Entire Route Groups

```typescript
// Protect all admin routes
const adminRouter = express.Router()
adminRouter.use(requireAdmin)
adminRouter.get('/users', (req, res) => { /* admin only */ })
adminRouter.get('/settings', (req, res) => { /* admin only */ })
app.use('/api/admin', adminRouter)
```

### Conditional Rendering Based on Roles

```tsx
function Dashboard() {
  const { hasRole } = useAuth()
  
  return (
    <div>
      <h1>Dashboard</h1>
      
      {hasRole('admin') && <AdminPanel />}
      {hasRole('manager') && <ManagerPanel />}
      {(hasRole('staff') || hasRole('manager')) && <StaffPanel />}
    </div>
  )
}
```

### Custom Hook for API Calls

```tsx
import { useAuth } from '../contexts/AuthContext'
import { useState, useCallback } from 'react'

interface ApiError {
  message: string
  status: number
}

export function useApiCall() {
  const { getToken } = useAuth()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

  const apiCall = useCallback(async <T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> => {
    setLoading(true)
    setError(null)
    
    try {
      const token = await getToken()
      
      const response = await fetch(endpoint, {
        ...options,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          ...options.headers
        }
      })
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      
      return await response.json()
    } catch (err) {
      const apiError: ApiError = {
        message: err instanceof Error ? err.message : 'Unknown error',
        status: 0
      }
      setError(apiError)
      throw apiError
    } finally {
      setLoading(false)
    }
  }, [getToken])

  return { apiCall, loading, error }
}

// Usage
function MyComponent() {
  const { apiCall, loading, error } = useApiCall()
  const [data, setData] = useState(null)

  const fetchData = async () => {
    try {
      const result = await apiCall('/api/some-endpoint')
      setData(result)
    } catch (err) {
      console.error('Failed to fetch data:', err)
    }
  }

  return (
    <div>
      <button onClick={fetchData} disabled={loading}>
        {loading ? 'Loading...' : 'Fetch Data'}
      </button>
      {error && <p>Error: {error.message}</p>}
      {data && <pre>{JSON.stringify(data, null, 2)}</pre>}
    </div>
  )
}
```

### Loading States

```tsx
function MyComponent() {
  const { loading, isAuthenticated } = useAuth()
  
  if (loading) {
    return <div>Checking authentication...</div>
  }
  
  if (!isAuthenticated) {
    return <div>Please log in</div>
  }
  
  return <div>Your authenticated content</div>
}
```

## 🛡️ Security Rules

### DO's
- ✅ Always use TypeScript for better type safety
- ✅ Always use `getToken()` for API calls
- ✅ Check roles on both frontend AND backend
- ✅ Use the provided middleware exactly as shown
- ✅ Handle loading states properly
- ✅ Add error handling to your API calls
- ✅ Validate environment variables on startup

### DON'Ts
- ❌ Don't store tokens in localStorage
- ❌ Don't trust frontend role checks alone
- ❌ Don't modify the AuthContext without understanding it
- ❌ Don't forget the error handler middleware
- ❌ Don't hardcode tokens
- ❌ Don't use JavaScript when TypeScript is available

## 🔧 Common Issues & Solutions

### "Token is invalid" Error
- Check your Keycloak server URL is correct
- Verify your realm and client ID match Keycloak config
- Ensure your client is properly configured in Keycloak

### "Access denied" Error
- Check user has the required role in Keycloak
- Verify role is assigned to the correct client or realm
- Check the role name matches exactly (case-sensitive)

### CORS Issues
- Add your frontend URL to "Valid Redirect URIs" in Keycloak
- Add your frontend domain to "Web Origins" in Keycloak

### TypeScript Compilation Errors
- Ensure all type definitions are installed
- Check that environment variables are properly typed
- Verify the Request interface extension is working

### Loading Never Finishes
- Check browser console for errors
- Verify Keycloak server is accessible
- Check network requests in browser dev tools

## 📝 Quick Reference

### AuthContext Hook (TypeScript)
```tsx
const {
  user,           // User | null
  isAuthenticated, // boolean
  loading,        // boolean
  signIn,         // () => void
  signOut,        // () => void
  getToken,       // () => Promise<string | undefined>
  hasRole         // (role: string) => boolean
} = useAuth()
```

### Backend Middleware (TypeScript)
```typescript
jwtCheck              // JWT validation middleware
requireAdmin          // Requires 'admin' role
requireRole('role')   // Requires specific role
requireAnyRole([...]) // Requires any of the listed roles
handleJwtError        // Error handler (add last)
```

### User Object Type
```typescript
interface User {
  id?: string
  username?: string
  email?: string
  name?: string
  firstName?: string
  lastName?: string
  roles?: string[]
  emailVerified?: boolean
}
```

### Request Type (Backend)
```typescript
interface Request extends express.Request {
  auth?: DecodedJwt  // Available after jwtCheck middleware
}
```

## 🎯 That's It!

Follow these steps exactly using TypeScript and you'll have working Keycloak authentication with full type safety. The provided code handles all the complex parts like token refresh, role management, and error handling.

Need help? Check the browser console and TypeScript compiler for detailed error messages and refer to the troubleshooting section above.