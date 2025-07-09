export const env = {
  KEYCLOAK_URL: process.env.KEYCLOAK_URL!,
  KEYCLOAK_REALM: process.env.KEYCLOAK_REALM!,
  KEYCLOAK_CLIENT_ID: process.env.KEYCLOAK_CLIENT_ID!,
  // Add other env vars as needed
}

// Validate required environment variables
const requiredEnvVars = ['KEYCLOAK_URL', 'KEYCLOAK_REALM', 'KEYCLOAK_CLIENT_ID']
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    throw new Error(`Missing required environment variable: ${envVar}`)
  }
} 