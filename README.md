# Keycloak Multi-Tenant Implementation Guide

## Table of Contents
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [Keycloak Setup](#-keycloak-setup-adding-tenant-info-to-tokens)
- [Backend Setup (Express.js + TypeScript)](#-backend-setup-expressjs--typescript)
- [Frontend Setup (React + TypeScript)](#-frontend-setup-react--typescript)
- [Security Rules](#-security-rules)

## Getting Started

### Prerequisites
- Node.js v20 or newer
- Yarn or npm
- A running Keycloak instance (e.g., via Docker)

### Install & Run

#### Backend
```bash
cd example-backend
cp .env.example .env
npm install
npm run dev
```

#### Frontend
```bash
cd example-frontend
cp .env.example .env
npm install
npm run dev
```

### Sample .env files

```bash
# example-backend/.env
KEYCLOAK_URL=https://auth.example.com
KEYCLOAK_REALM=myrealm
KEYCLOAK_CLIENT_ID=my-client

# example-frontend/.vite.env
VITE_KEYCLOAK_URL=https://auth.example.com
VITE_KEYCLOAK_REALM=myrealm
VITE_KEYCLOAK_CLIENT_ID=my-client
```

## Environment Variables

| Name                    | Required | Description                                     | Example                   |
|-------------------------|:--------:|-------------------------------------------------|---------------------------|
| KEYCLOAK_URL            |   Yes    | Base URL of the Keycloak server                 | https://auth.example.com  |
| KEYCLOAK_REALM          |   Yes    | Keycloak realm name                             | myrealm                   |
| KEYCLOAK_CLIENT_ID      |   Yes    | Keycloak client ID for the backend              | my-client                 |
| VITE_KEYCLOAK_URL       |   Yes    | Base URL of the Keycloak server (frontend)      | https://auth.example.com  |
| VITE_KEYCLOAK_REALM     |   Yes    | Keycloak realm name (frontend)                  | myrealm                   |
| VITE_KEYCLOAK_CLIENT_ID |   Yes    | Keycloak client ID (frontend)                   | my-client                 |
| PORT                    |    No    | Backend server port (default: 3001)             | 4000                      |

## Callouts & Disclaimers

- ⚠️ The in-memory `userPermissionsDb` in `src/middleware/tenantContext.ts` is a **placeholder**. Replace it with your own database or ACL service.
- 🚧 This template omits production hardening (CORS, rate-limiting, Helmet, structured logging). Add these before going live.
- ⚠️ There is no `/me/permissions` endpoint by default—either implement it or adjust your frontend accordingly.

Our architecture uses a powerful, clean separation of concerns for security in a multi-tenant environment. We use Keycloak as a centralized **Identity Provider (IdP)**. Its sole responsibility is to **authenticate users** and assert which **tenants (companies) they belong to** using Keycloak's "Groups" feature.

All fine-grained authorization—such as determining if a user is an `admin` within a specific company or has access to a particular product—is handled **entirely within the application itself**. The application's backend is the single source of truth for permissions. This philosophy prevents complexity in Keycloak, keeps user management simple, and empowers each tenant to have its own robust and context-aware access control.

This guide shows you how to implement this architecture in your React + Express.js projects using TypeScript.

> **Note**: Always use TypeScript for better type safety and developer experience. All examples below are in TypeScript.

---

## 🚀 Keycloak Setup: Adding Tenant Info to Tokens

Before touching the code, you must configure Keycloak to include the user's group memberships (tenants) in the access token. This is how the backend will know which companies a user belongs to.

1.  In your Keycloak admin console, navigate to your client.
2.  Go to the **Client Scopes** tab (e.g., `your-client-dedicated-scope`).
3.  Click on the **Mappers** tab.
4.  Click **Add mapper** and choose **By Configuration**.
5.  Select the **Group Membership** mapper.
6.  Give it a name (e.g., "groups"). The **Token Claim Name** will also be `groups`. This is the property that will appear in the JWT.
7.  Turn **ON** the **Full group path** setting. This ensures group names are unique (e.g., `/company-a` instead of just `company-a`).
8.  Click **Save**.

After this, a logged-in user's access token will contain a `groups` array:
```json
{
  "sub": "user-uuid-12345",
  "groups": [
    "/company-a",
    "/company-b"
  ],
  ...
}
```

---

## 🔧 Backend Setup (Express.js + TypeScript)

The backend is responsible for enforcing all authorization rules based on the tenant context.

### Step 1: Install Dependencies

```bash
npm install express express-jwt jwks-rsa
npm install -D @types/express @types/node typescript ts-node
```

### Step 2: Update Authentication Middleware (`src/middleware/auth.ts`)

This middleware is now only responsible for **authentication**. It verifies the JWT and attaches the user's identity (`req.auth`) to the request. All role-based logic has been removed.

```typescript:src/middleware/auth.ts
import { expressjwt } from "express-jwt";
import type { GetVerificationKey } from "express-jwt";
import { expressJwtSecret } from "jwks-rsa";
import { env } from "../config/env";
import type { NextFunction, Request, Response } from "express";

interface DecodedJwt {
   sub: string;
   groups?: string[]; // The `groups` claim from Keycloak
   // ... other standard claims
}

declare global {
   namespace Express {
      export interface Request {
         auth?: DecodedJwt;
      }
   }
}

const keycloakIssuer = `${env.KEYCLOAK_URL}/realms/${env.KEYCLOAK_REALM}`;

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

export function handleJwtError(err: any, req: Request, res: Response, next: NextFunction) {
   if (err.name === 'UnauthorizedError') {
      let message = "Access token is invalid or expired.";
      // ... error handling logic ...
      res.status(401).json({ message, error: "UNAUTHORIZED", code: err.code });
   } else {
      next(err);
   }
}
```

### Step 3: Create Tenant Context Middleware (`src/middleware/tenantContext.ts`)

This is the core of your new authorization system. It runs after `jwtCheck` and establishes the user's permissions for the company they are currently working in.

```typescript:src/middleware/tenantContext.ts
import type { Request, Response, NextFunction } from 'express';

// Extend Express Request to include our tenant context
declare global {
   namespace Express {
      export interface Request {
         tenant?: {
            id: string;
            roles: string[]; // Roles specific to this tenant
            products: string[]; // Products accessible in this tenant
         };
      }
   }
}

// MOCK DATABASE: In a real app, you'd fetch this from a database.
const userPermissionsDb = {
  'user-uuid-12345': {
    'company-a': { roles: ['admin'], products: ['product1', 'product3'] },
    'company-b': { roles: ['user'], products: ['product2'] },
  },
};

export async function tenantContext(req: Request, res: Response, next: NextFunction) {
  const tenantId = req.headers['x-tenant-id'] as string;
  const userId = req.auth?.sub;
  const userGroups = req.auth?.groups || [];

  if (!userId || !tenantId) {
    return res.status(400).json({ message: 'User ID and X-Tenant-ID header are required.' });
  }

  // 1. Verify user is a member of the tenant (via Keycloak group)
  if (!userGroups.includes(`/${tenantId}`)) {
     return res.status(403).json({ message: `Access denied: You are not a member of company '${tenantId}'.` });
  }
  
  // 2. Fetch user's permissions for this tenant from your application database
  const permissions = userPermissionsDb[userId]?.[tenantId];
  if (!permissions) {
      return res.status(403).json({ message: `Access denied: You have no assigned role in this company.` });
  }

  // 3. Attach tenant context to the request
  req.tenant = {
    id: tenantId,
    roles: permissions.roles,
    products: permissions.products,
  };

  next();
}
```

### Step 4: Create Tenant-Aware Role Middleware (`src/middleware/requireTenantRole.ts`)

This middleware checks for roles within the context established by `tenantContext`.

```typescript:src/middleware/requireTenantRole.ts
import type { Request, Response, NextFunction } from 'express';

export function requireTenantRole(requiredRole: string | string[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    if (!req.tenant) {
      return res.status(500).json({ message: 'Server error: Company context not established.' });
    }
    const userRoles = req.tenant.roles;
    const required = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
    const hasRole = required.some(role => userRoles.includes(role));

    if (hasRole) {
      return next();
    }
    res.status(403).json({ message: `Access denied: Requires one of these roles: ${required.join(', ')}` });
  };
}
```

### Step 5: Apply Middleware to Your Routes (`src/index.ts`)

Structure your Express app to use these new middleware correctly.

```typescript:src/index.ts
import express from 'express';
import { jwtCheck, handleJwtError } from './middleware/auth';
import { tenantContext } from './middleware/tenantContext';
import { requireTenantRole } from './middleware/requireTenantRole';

const app = express();

// A router for all authenticated, tenant-specific API calls
const tenantApi = express.Router();

// Apply middleware in order:
// 1. Validate the JWT to get `req.auth`
tenantApi.use(jwtCheck);
// 2. Establish tenant context to get `req.tenant`
tenantApi.use(tenantContext);

// Example route accessible to any valid member of the tenant
tenantApi.get('/projects', (req, res) => {
  res.json({ message: `Project list for company ${req.tenant?.id}` });
});

// Example route that requires the 'admin' role within that specific tenant
tenantApi.get('/settings', requireTenantRole('admin'), (req, res) => {
  res.json({ message: `Admin settings for company ${req.tenant?.id}` });
});

// Mount the tenant-aware router
app.use('/api/v1', tenantApi);

// Add JWT error handler AFTER all routes
app.use(handleJwtError);

app.listen(3001, () => console.log('Server running on port 3001'));
```

---

##  frontend-setup Frontend Setup (React + TypeScript)

The frontend no longer checks roles directly. Instead, it securely stores the user's identity and provides the necessary context (`tenantId`) for all API calls.

### Step 1: Update AuthContext (`src/contexts/AuthContext.tsx`)

The `AuthContext` is now simpler. It no longer stores or checks for roles.

```typescript:src/contexts/AuthContext.tsx
// ...
interface User {
   id?: string;
   username?: string;
   // `roles` array is removed
}

interface AuthContextType {
   // `hasRole` function is removed
   // ...
}

// ... in AuthProvider
const parseUser = useCallback(async (kc: Keycloak) => {
  // Logic to parse roles is removed
}, []);
// ...
```

### Step 2: Create a Tenant Management System (Conceptual)

In a real application, you would need:
1.  **A TenantContext:** A new React context to store the `currentTenantId`.
2.  **A Tenant Selector:** If a user belongs to multiple groups (companies), you must show a UI after login for them to select which company they want to work in. This selection would set the `currentTenantId` in your `TenantContext`.

### Step 3: Update API Hook to be Tenant-Aware (`src/hooks/useApiCall.ts`)

Your `useApiCall` hook is now responsible for sending the `X-Tenant-ID` header.

```typescript:src/hooks/useApiCall.ts
import { useAuth } from '../contexts/AuthContext';
// import { useTenant } from '../contexts/TenantContext'; // You would create this

export function useApiCall() {
  const { getToken } = useAuth();
  // const { currentTenantId } = useTenant(); // Get selected tenant from context

  const apiCall = useCallback(async <T>(
    tenantId: string, // Pass tenantId directly for this example
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> => {
    const token = await getToken();
    
    const response = await fetch(`/api/v1${endpoint}`, { // Note the /v1 path
      ...options,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'X-Tenant-ID': tenantId, // The crucial header
        ...options.headers,
      },
    });
    
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    return response.json();
  }, [getToken]);

  return { apiCall };
}
```

### Step 4: Use in Components

UI rendering based on permissions is now driven by data fetched from the backend, not by the content of the JWT.

```tsx
function Dashboard() {
  const { apiCall } = useApiCall();
  const [permissions, setPermissions] = useState({ roles: [], products: [] });
  // Assume 'company-a' is the selected tenant
  const currentTenantId = 'company-a';

  useEffect(() => {
    // Fetch the user's permissions for the current tenant when the app loads
    apiCall(currentTenantId, '/me/permissions')
      .then(setPermissions)
      .catch(console.error);
  }, [apiCall, currentTenantId]);

  const hasPermission = (role: string) => permissions.roles.includes(role);

  return (
    <div>
      <h1>Dashboard for {currentTenantId}</h1>
      
      {hasPermission('admin') && <AdminPanel />}
      {permissions.products.includes('product1') && <ProductOneWidget />}
    </div>
  );
}
```

## 🔐 Security Rules

### DO's
- ✅ **Centralize Authorization**: All permission logic lives in your backend.
- ✅ **Use Keycloak Groups for Tenancy**: Groups are a robust way to manage which users belong to which company.
- ✅ **Send Tenant Context**: Always send the `X-Tenant-ID` header for API calls that require it.
- ✅ **Fetch Permissions from API**: The frontend should query an endpoint to get the user's permissions for the active tenant to correctly render the UI.
- ✅ **Validate Environment Variables**: Ensure your backend has all necessary Keycloak configuration on startup.

### DON'Ts
- ❌ **Never Trust the Frontend**: Do not make authorization decisions based on data sent from the client, other than the JWT and the `X-Tenant-ID`.
- ❌ **Don't Put Roles in the JWT**: Avoid putting application-specific roles (`admin`, `manager`) in the JWT. This creates a distributed, hard-to-manage authorization system. The JWT should only contain identity and tenant membership.
- ❌ **Don't Forget the JWT Error Handler**: It's crucial for providing clear error messages to the client.
- ❌ **Don't Mix Authorization Models**: Stick to a single, clear model. In this architecture, the application is the sole authority on permissions.