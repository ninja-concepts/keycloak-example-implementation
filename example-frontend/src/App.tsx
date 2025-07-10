import { useState } from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { useApiCall } from './hooks/useApiCall';
import './App.css';

function MyComponent() {
  const { user, isAuthenticated, signIn, signOut, loading: authLoading } = useAuth();
  const { apiCall, loading: apiLoading } = useApiCall();
  
  const [apiResponse, setApiResponse] = useState<any>(null);
  const [apiError, setApiError] = useState<string | null>(null);

  // In a real app, this would come from a global state/context after user selection
  const [currentTenantId, setCurrentTenantId] = useState('company-a');

  const makeApiCall = async (endpoint: string) => {
    setApiResponse(null);
    setApiError(null);
    try {
      // Pass the current tenantId to our updated apiCall hook
      const data = await apiCall(currentTenantId, endpoint);
      setApiResponse(data);
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
      <button onClick={signOut}>Sign Out</button>

      <div className="card">
        <h3>Multi-Tenant API Demo</h3>

        <div className="tenant-selector">
          <span>Operating In:</span>
          <button 
            className={currentTenantId === 'company-a' ? 'active' : ''}
            onClick={() => setCurrentTenantId('company-a')}
          >
            Company A (Admin)
          </button>
          <button 
            className={currentTenantId === 'company-b' ? 'active' : ''}
            onClick={() => setCurrentTenantId('company-b')}
          >
            Company B (User)
          </button>
        </div>
        
        <p>
          You are currently acting as a user in <strong>{currentTenantId}</strong>. 
          The API will respond based on your permissions within this company.
        </p>
        <div className="buttons">
          <button onClick={() => makeApiCall('/projects')} disabled={apiLoading}>
            Fetch Projects (Should Succeed)
          </button>
          <button onClick={() => makeApiCall('/settings')} disabled={apiLoading}>
            Fetch Settings (Requires Admin)
          </button>
           <button onClick={() => makeApiCall('/products/product1')} disabled={apiLoading}>
            Fetch Product 1 (Requires Product Access)
          </button>
        </div>

        {apiLoading && <div>Loading...</div>}
        
        {apiError && (
          <div>
            <h3>❌ Access Denied or Error:</h3>
            <pre className="error">{apiError}</pre>
          </div>
        )}

        {apiResponse && (
          <div>
            <h3>✅ Access Granted:</h3>
            <pre>{JSON.stringify(apiResponse, null, 2)}</pre>
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
