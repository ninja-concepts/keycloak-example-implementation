import express from 'express';
import { jwtCheck, requireAnyRole, handleJwtError } from './middleware/auth';
import { canAccessProject } from './middleware/projectAuth';

const app = express();
const port = process.env.PORT || 3001;

// Apply JWT validation to all API routes
// Any route under /api requires a valid token
app.use('/api', jwtCheck, handleJwtError);

// Public route (no auth needed - doesn't go through the /api middleware)
app.get('/public', (req, res) => {
  res.json({ message: 'This endpoint is public.' });
});

// Protected route (just needs a valid token)
app.get('/api/protected', (req, res) => {
  res.json({ 
    message: 'You have a valid token.',
    userId: req.auth?.sub,
  });
});

// Resource-specific protected route
// 1. `jwtCheck` runs because of `app.use('/api', ...)`
// 2. `requireAnyRole` checks for a basic role from Keycloak.
// 3. `canAccessProject` runs our app's specific business logic.
app.get('/api/projects/:projectId', 
  requireAnyRole(['user', 'manager', 'admin']), // User must have at least one of these roles
  canAccessProject, // Then, check if they can access this specific project
  (req, res) => {
    // If we get here, both checks passed.
    res.json({ 
      message: `Successfully accessed project data for project ID: ${req.params.projectId} by user ${req.auth?.sub}`
    });
  }
);

// User info route from previous example - still useful
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
});


app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

export default app;