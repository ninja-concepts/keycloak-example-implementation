import { useState } from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { useApiCall } from './hooks/useApiCall';
import './App.css';

function MyComponent() {
  const { user, isAuthenticated, signIn, signOut, hasRole, loading: authLoading } = useAuth();
  const { apiCall, loading: apiLoading } = useApiCall();
  
  const [projectData, setProjectData] = useState<any>(null);
  const [apiError, setApiError] = useState<string | null>(null);

  const fetchProject = async (projectId: string) => {
    setProjectData(null);
    setApiError(null);
    try {
      // The backend will check if this user has access to this specific project
      const data = await apiCall(`/api/projects/${projectId}`);
      setProjectData(data);
    } catch (err: any) {
      setApiError(err.message);
    }
  };

  if (authLoading) return <div>Authenticating...</div>;
  if (!isAuthenticated) return <button onClick={signIn}>Sign In</button>;

  return (
    <div>
      <h1>Welcome, {user?.name}!</h1>
      <p>Your User ID: <code>{user?.id}</code></p>
      <p>Your Roles: <code>{user?.roles?.join(', ')}</code></p>
      <button onClick={signOut}>Sign Out</button>

      {/* Role-based UI element */}
      {hasRole('admin') && (
        <button>This button is visible only for admin users</button>
      )}

      <div className="card">
        <h3>Resource Access Control Demo</h3>
        <p>
          Try accessing two different projects. The backend will grant access to 
          "My Project" but deny access to "Other Project" based on your User ID.
        </p>
        <div className="buttons">
          {/* This project is owned by the logged-in user, so access will be granted */}
          <button onClick={() => fetchProject('project-123')} disabled={apiLoading}>
            Fetch "My Project" (Should Succeed)
          </button>
          {/* This project is owned by someone else, so access will be denied (403 Forbidden) */}
          <button onClick={() => fetchProject('project-456')} disabled={apiLoading}>
            Fetch "Other Project" (Should Fail)
          </button>
        </div>

        {apiLoading && <div>Loading...</div>}
        {apiError && <div className="error">API Error: {apiError}</div>}
        {projectData && (
          <div>
            <h3>✅ Access Granted:</h3>
            <pre>{JSON.stringify(projectData, null, 2)}</pre>
          </div>
        )}
      </div>
    </div>
  );
}

function App() {
  return (
    <AuthProvider>
      <MyComponent />
    </AuthProvider>
  );
}

export default App;
