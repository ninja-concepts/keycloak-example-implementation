import express from 'express';
import { jwtCheck, handleJwtError } from './middleware/auth';
import { tenantContext } from './middleware/tenantContext';
import { requireTenantRole } from './middleware/requireTenantRole';

const app = express();
const port = process.env.PORT || 3001;

// --- Public Routes ---
// Public routes are defined before any authentication middleware.
app.get('/public', (req, res) => {
  res.json({ message: 'This endpoint is public and requires no authentication.' });
});


// --- Tenant-Aware API Routes ---
// All routes that deal with tenant-specific data are grouped under this router.
const tenantApi = express.Router();

// Apply middleware in a specific order for this router:
// 1. `jwtCheck`: First, authenticate the user and get `req.auth`.
// 2. `tenantContext`: Next, establish the company context and get `req.tenant`.
tenantApi.use(jwtCheck);
tenantApi.use(tenantContext);

// --- Example Tenant-Aware Endpoints ---

// This route is accessible as long as the user is a valid member of the tenant
// specified in the 'X-Tenant-ID' header.
tenantApi.get('/projects', (req, res) => {
  res.json({ 
    message: `Successfully fetched project list for company '${req.tenant?.id}'`,
    user: req.auth?.sub
  });
});

// This route requires the user to have the 'admin' role within the active tenant.
// The `requireTenantRole` middleware uses the context established by `tenantContext`.
tenantApi.get('/settings', requireTenantRole('admin'), (req, res) => {
  res.json({ 
    message: `Successfully accessed admin settings for company '${req.tenant?.id}'` 
  });
});

// This route demonstrates checking for access to a specific product, which is also
// part of the permissions loaded into `req.tenant`.
tenantApi.get('/products/product1', (req, res) => {
    if (req.tenant?.products.includes('product1')) {
        return res.json({ message: 'Access to Product 1 granted!' });
    }
    return res.status(403).json({ message: 'Access denied: Your company does not have access to Product 1.' });
});

// Mount our tenant-aware router under the `/api/v1` path.
// All requests to `/api/v1/*` will now be handled by this router.
app.use('/api/v1', tenantApi);


// --- Global Error Handler ---
// The JWT error handler must be registered AFTER the routes that use `jwtCheck`.
// It will catch any errors thrown by the `express-jwt` middleware.
app.use(handleJwtError);


app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

export default app;