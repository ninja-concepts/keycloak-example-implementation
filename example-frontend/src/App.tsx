import { useState } from 'react';
import { AuthProvider, useAuth } from './contexts/AuthContext';
import { useApiCall } from './hooks/useApiCall';
import './App.css';

function MyComponent() {
  const { user, isAuthenticated, signIn, signOut, hasRole, loading: authLoading } = useAuth();
  const { apiCall, loading: apiLoading, error, } = useApiCall();
  const [userInfo, setUserInfo] = useState<any>(null);

  const handleFetchUserInfo = async () => {
    try {
      const data = await apiCall('/api/user-info');
      setUserInfo(data);
    } catch (err) {
      // error is already set by the hook
      setUserInfo(null);
    }
  };

  if (authLoading) return <div>Loading...</div>;

  if (!isAuthenticated) {
    return <button onClick={() => signIn()}>Sign In</button>;
  }

  return (
    <div>
      <h1>Welcome, {user?.name}!</h1>
      <p>Email: {user?.email}</p>

      {hasRole('admin') && (
        <button>This button should be visible only for admin users</button>
      )}

      <button onClick={() => signOut()}>Sign Out</button>

      <div className="card">
        <button onClick={handleFetchUserInfo} disabled={apiLoading}>
          {apiLoading ? 'Fetching User Info...' : 'Fetch User Info from API'}
        </button>
        {error && <p className="error">Error: {error.message}</p>}
        {userInfo && (
          <div>
            <h3>API Response:</h3>
            <pre>{JSON.stringify(userInfo, null, 2)}</pre>
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
