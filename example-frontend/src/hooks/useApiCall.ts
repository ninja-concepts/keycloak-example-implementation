import { useAuth } from '../contexts/AuthContext';
import { useState, useCallback } from 'react';

interface ApiError {
  message: string;
  status: number;
}

/**
 * Custom hook for making authenticated, tenant-aware API calls.
 * This hook is now responsible for adding both the Authorization token
 * and the required X-Tenant-ID header to every request.
 */
export function useApiCall() {
  const { getToken } = useAuth();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  const apiCall = useCallback(async <T>(
    // The `tenantId` is now a required parameter for making API calls.
    tenantId: string,
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> => {
    setLoading(true);
    setError(null);

    if (!tenantId) {
      const tenantError = { message: 'Tenant ID is required for API calls.', status: 400 };
      setError(tenantError);
      throw tenantError;
    }

    try {
      const token = await getToken();

      // All tenant-aware endpoints are now under the `/api/v1` prefix.
      const response = await fetch(`/api/v1${endpoint}`, {
        ...options,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          // Add the crucial tenant header for the backend middleware.
          'X-Tenant-ID': tenantId,
          ...options.headers,
        },
      });

      if (!response.ok) {
        // Attempt to parse error response from the server for better messages.
        const errorBody = await response.json().catch(() => ({ message: 'Failed to parse error response.' }));
        throw new Error(`HTTP error! status: ${response.status} - ${errorBody.message || 'Unknown server error'}`);
      }

      const text = await response.text();
      return text ? JSON.parse(text) : {} as T;

    } catch (err) {
      const apiError: ApiError = {
        message: err instanceof Error ? err.message : 'An unknown error occurred.',
        status: err instanceof Error && 'status' in err ? (err as any).status : 0,
      };
      setError(apiError);
      throw apiError;
    } finally {
      setLoading(false);
    }
  }, [getToken]);

  return { apiCall, loading, error };
} 