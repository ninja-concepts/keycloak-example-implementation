import { useAuth } from '../contexts/AuthContext'
import { useState, useCallback } from 'react'

interface ApiError {
  message: string
  status: number
}

export function useApiCall() {
  const { getToken } = useAuth()
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

  const apiCall = useCallback(async <T>(
    endpoint: string, 
    options: RequestInit = {}
  ): Promise<T> => {
    setLoading(true)
    setError(null)
    
    try {
      const token = await getToken()
      
      const response = await fetch(endpoint, {
        ...options,
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json',
          ...options.headers
        }
      })
      
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`)
      }
      
      const text = await response.text();
      return text ? JSON.parse(text) : {} as T;

    } catch (err) {
      const apiError: ApiError = {
        message: err instanceof Error ? err.message : 'Unknown error',
        status: 0
      }
      setError(apiError)
      throw apiError
    } finally {
      setLoading(false)
    }
  }, [getToken])

  return { apiCall, loading, error }
} 