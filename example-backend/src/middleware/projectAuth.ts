import type { Request, Response, NextFunction } from 'express';
import { getRolesFromToken } from './auth'; // Import from our auth middleware

// Mock database of project ownership. In a real app, you'd query a database.
const projectOwners: Record<string, string> = {
  'project-123': 'user-id-of-person-who-is-logged-in', // This will be replaced dynamically
  'project-456': 'another-user-id-abc-123',
};

export function canAccessProject(req: Request, res: Response, next: NextFunction) {
  const projectId = req.params.projectId;
  const userId = req.auth?.sub; // User ID from the JWT

  if (!userId) {
    // This should not happen if jwtCheck is used, but it's good practice
    return res.status(401).json({ message: 'Authentication required: User ID missing.' });
  }

  // Dynamically set the owner of project-123 to the current user for demonstration
  projectOwners['project-123'] = userId;

  const project = projectOwners[projectId];
  if (!project) {
    return res.status(404).json({ message: 'Project not found.' });
  }

  // 1. Check for resource ownership (the most specific rule)
  if (projectOwners[projectId] === userId) {
    console.log(`Access granted: User ${userId} owns project ${projectId}.`);
    return next(); // User is the owner, grant access.
  }

//   // 2. Check for role-based access (a broader rule)
//   const roles = getRolesFromToken(req.auth);
//   if (roles.includes('manager') || roles.includes('admin')) {
//     console.log(`Access granted: User ${userId} has role 'manager' or 'admin' for project ${projectId}.`);
//     return next(); // Managers/admins can view any project.
//   }

  // 3. If no rules match, deny access.
  console.warn(`Access DENIED: User ${userId} cannot access project ${projectId}.`);
  return res.status(403).json({ 
    message: 'Access denied: You do not have permission to view this resource.',
    error: 'FORBIDDEN'
  });
} 