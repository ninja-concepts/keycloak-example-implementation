import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import type { ReactNode } from 'react';
import Keycloak from 'keycloak-js'
import { initKeycloak } from '../lib/keycloak'

interface User {
   id?: string
   username?: string
   email?: string
   name?: string
   firstName?: string
   lastName?: string
   // The `roles` field is removed, as global roles are no longer used.
   // Tenant-specific roles are handled by the backend.
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
   // The `hasRole` function is removed. All role checks are now API-driven
   // and context-dependent (i.e., based on the selected tenant).
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
            // We no longer parse `roles` here. The user's permissions are contextual
            // to the selected tenant and will be fetched from the API.
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

   // The `hasRole` function has been removed.

   return (
      <AuthContext.Provider value={{
         keycloak: keycloakInstance,
         user,
         loading,
         isAuthenticated: !!keycloakInstance?.authenticated,
         signIn,
         signOut,
         getToken,
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