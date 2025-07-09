import express from 'express'
import { jwtCheck, requireAdmin, requireRole, requireAnyRole, handleJwtError } from './middleware/auth'

const app = express()
const port = process.env.PORT || 3001;

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

// IMPORTANT: Add error handler AFTER all routes
app.use(handleJwtError)

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

export default app