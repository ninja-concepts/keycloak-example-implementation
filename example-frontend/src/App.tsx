import { AuthProvider, useAuth } from './contexts/AuthContext';
import './App.css';

function MyComponent() {
  const { user, isAuthenticated, signIn, signOut, hasRole, loading } = useAuth()
  
  if (loading) return <div>Loading...</div>
  
  if (!isAuthenticated) {
    return <button onClick={() => signIn()}>Sign In</button>
  }
  
  return (
    <div>
      <h1>Welcome, {user?.name}!</h1>
      <p>Email: {user?.email}</p>
      
      {hasRole('admin') && (
        <button>Admin Panel</button>
      )}
      
      <button onClick={() => signOut()}>Sign Out</button>
    </div>
  )
}


function App() {
  return (
    <AuthProvider>
      <MyComponent />
    </AuthProvider>
  )
}

export default App
