import Keycloak from 'keycloak-js';

const keycloakConfig = {
   url: import.meta.env.VITE_KEYCLOAK_URL!, // Vite uses import.meta.env
   realm: import.meta.env.VITE_KEYCLOAK_REALM!,
   clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID!
};

const keycloak = new Keycloak(keycloakConfig);

/**
 * Because React Strict-Mode (development) intentionally mounts components twice and
 * because multiple places in the codebase may try to call `initKeycloak`, we need
 * to guarantee that `keycloak.init` is executed **only once**.  Invoking it again
 * throws `Error: A 'Keycloak' instance can only be initialized once.`  We solve
 * this by memoising the initialisation promise.
 */
let initPromise: Promise<Keycloak> | null = null;

/**
 * Initializes Keycloak instance and makes it available globally.
 *
 * @param {() => void} onAuthenticatedCallback - Callback function to execute after successful authentication.
 * @returns {Promise<Keycloak>} A promise that resolves to the Keycloak instance.
 */
export const initKeycloak = (onAuthenticatedCallback: (kc: Keycloak) => void): Promise<Keycloak> => {
   // If initialisation already in progress or finished, just hook into that
   if (initPromise) {
      initPromise.then((kc) => {
         if (kc.authenticated) {
            // Fire callback for late subscribers that still care about auth state
            onAuthenticatedCallback(kc)
         }
      })
      return initPromise
   }

   initPromise = new Promise((resolve, reject) => {
      console.log('Keycloak: Attempting init with onLoad: login-required and checkLoginIframe: false');
      keycloak.init({
         onLoad: 'login-required',
         pkceMethod: 'S256', // Recommended for public clients
         checkLoginIframe: false, // Explicitly disable session status iframe
      })
         .then((authenticated) => {
            console.log(`Keycloak: Init completed. Authenticated: ${authenticated}`);
            if (authenticated) {
               console.log('Keycloak: User is authenticated');
               onAuthenticatedCallback(keycloak);
               resolve(keycloak);
            } else {
               console.warn('Keycloak: User is not authenticated after init with login-required.');
               // For login-required, if not authenticated, Keycloak should have redirected.
               // If we reach here without authentication, it might mean the redirect didn't happen or was blocked.
               resolve(keycloak); // Still resolve, AuthContext will handle state based on isAuthenticated
            }

            // Token refresh mechanism - only set up if authenticated
            if (authenticated) {
               setInterval(() => {
                  keycloak.updateToken(70).then((refreshed) => {
                     if (refreshed) {
                        console.log('Keycloak: Token refreshed');
                     } else {
                        if (keycloak.tokenParsed && typeof keycloak.tokenParsed.exp === 'number' && typeof keycloak.timeSkew !== 'undefined') {
                           console.log('Keycloak: Token not refreshed, valid for ' + Math.round(keycloak.tokenParsed.exp + keycloak.timeSkew - new Date().getTime() / 1000) + ' seconds');
                        } else {
                           console.log('Keycloak: Token not refreshed, unable to determine validity (tokenParsed or exp missing, or timeSkew undefined).');
                        }
                     }
                  }).catch(() => {
                     console.error('Keycloak: Failed to refresh token');
                  });
               }, 60000); // Refresh every 60 seconds
            }
         })
         .catch((error) => {
            console.error('Keycloak: Initialization Failed during init()', error);
            // Allow subsequent attempts if this one failed
            initPromise = null;
            reject(error);
         });
   });

   return initPromise;
};

export default keycloak; 