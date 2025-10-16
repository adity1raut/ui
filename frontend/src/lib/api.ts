import axios, { AxiosRequestConfig } from 'axios';
import { toast } from 'react-hot-toast';
import { setGlobalNetworkError } from '../utils/networkErrorUtils';
import { isOnLoginPage } from '../utils/routeUtils';
import {
  getAccessToken,
  clearTokens,
  isTokenExpired,
  refreshAccessToken,
  setTokens,
} from '../components/login/tokenUtils';

export const api = axios.create({
  baseURL: process.env.VITE_BASE_URL,
  timeout: 60000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add request interceptor to include JWT token in headers
api.interceptors.request.use(
  async config => {
    let token = getAccessToken();
    // If token is expired, try to refresh
    if (isTokenExpired(token)) {
      token = await refreshAccessToken(api);
    }
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  error => {
    return Promise.reject(error);
  }
);

// Add response interceptors with proper error typing
api.interceptors.response.use(
  response => {
    console.log('Axios Interceptor: Successful response. Clearing network error.');
    setGlobalNetworkError(false);
    return response;
  },
  async (error: unknown) => {
    if (!axios.isAxiosError(error)) {
      console.error('Axios Interceptor: An unknown error occurred.', error);
      toast.error('An unknown error occurred.');
      return Promise.reject(error);
    }

    const originalRequest = error.config as AxiosRequestConfig & { _retry?: boolean };
    const errorMessage =
      error.response?.data?.message || error.response?.data?.error || error.message;
    const isAuthCheck = error.config?.url?.includes('/api/me');

    const isLoginEndpoint = error.config?.url?.includes('/login');

    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !isAuthCheck &&
      !isLoginEndpoint
    ) {
      console.warn('Axios Interceptor: 401 Unauthorized. Attempting token refresh.');
      originalRequest._retry = true;
      const newToken = await refreshAccessToken(api);
      if (newToken) {
        originalRequest.headers = originalRequest.headers || {};
        originalRequest.headers.Authorization = `Bearer ${newToken}`;
        return api(originalRequest);
      } else {
        console.error('Axios Interceptor: Token refresh failed. Redirecting to login.');
        clearTokens();
        if (!isOnLoginPage()) {
          toast.error('Session expired. Please log in again.');
        }

        window.location.href = '/login';
        return Promise.reject(error);
      }
    }

    if (!error.response) {
      console.error(
        'Axios Interceptor: Network error (no response). Setting global network error.'
      );
      setGlobalNetworkError(true);
    } else {
      console.error('Axios Interceptor: API error response.', error.response);
      const isLoginEndpoint = error.config?.url?.includes('/login');
      const shouldSuppressToast = (error.response.status === 401 && isAuthCheck) || isLoginEndpoint;

      if (!shouldSuppressToast) {
        // For other errors, show toast but use a consistent ID to prevent duplicates
        const toastId = `api-error-${error.response?.status || 'unknown'}`;
        toast.error(errorMessage, { id: toastId });
      }
    }

    return Promise.reject(error);
  }
);

// Helper function to get WebSocket URL with proper protocol and base URL
export const getWebSocketUrl = (path: string): string => {
  const baseUrl = process.env.VITE_BASE_URL || '';

  const wsProtocol = baseUrl.startsWith('https') ? 'wss' : 'ws';

  const baseUrlWithoutProtocol = baseUrl.replace(/^https?:\/\//, '');

  return `${wsProtocol}://${baseUrlWithoutProtocol}${path}`;
};

// ===================================
// GitHub SSO API Functions
// ===================================

/**
 * Initiates GitHub OAuth flow by redirecting to backend OAuth endpoint
 */
export const initiateGitHubLogin = (): void => {
  const baseUrl = process.env.VITE_BASE_URL || 'http://localhost:4000';
  window.location.href = `${baseUrl}/auth/github`;
};

/**
 * Handles GitHub OAuth callback by extracting tokens from URL
 * This should be called on the callback page after GitHub redirects back
 */
export const handleGitHubCallback = (): {
  success: boolean;
  accessToken?: string;
  refreshToken?: string;
  error?: string;
} => {
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const accessToken = urlParams.get('token');
    const refreshToken = urlParams.get('refreshToken');
    const error = urlParams.get('error');

    if (error) {
      console.error('GitHub OAuth error:', error);
      return { success: false, error };
    }

    if (accessToken && refreshToken) {
      // Store tokens using your existing token utility
      setTokens(accessToken, refreshToken);
      
      // Clean up URL by removing query parameters
      window.history.replaceState({}, document.title, window.location.pathname);
      
      return { success: true, accessToken, refreshToken };
    }

    return { success: false, error: 'No tokens received from OAuth callback' };
  } catch (error) {
    console.error('Error handling GitHub callback:', error);
    return { 
      success: false, 
      error: error instanceof Error ? error.message : 'Unknown error occurred' 
    };
  }
};

/**
 * Alternative callback handler if backend returns JSON response
 * Use this if you modify backend to return JSON instead of redirecting
 */
export const exchangeGitHubCode = async (code: string, state: string) => {
  try {
    const response = await api.get('/auth/github/callback', {
      params: { code, state },
    });

    const { access_token, refresh_token, user } = response.data;

    if (access_token && refresh_token) {
      setTokens(access_token, refresh_token);
      return { success: true, user };
    }

    return { success: false, error: 'Invalid response from server' };
  } catch (error) {
    console.error('GitHub code exchange failed:', error);
    if (axios.isAxiosError(error)) {
      return {
        success: false,
        error: error.response?.data?.error || 'Failed to authenticate with GitHub',
      };
    }
    return { success: false, error: 'Unknown error occurred' };
  }
};

/**
 * Check if user is authenticated via GitHub SSO
 * Returns user info if authenticated
 */
export const checkGitHubAuth = async () => {
  try {
    const response = await api.get('/api/me');
    return { success: true, user: response.data };
  } catch (error) {
    console.error('GitHub auth check failed:', error);
    return { success: false, error: 'Not authenticated' };
  }
};

/**
 * Utility to check if current session is from GitHub SSO
 */
export const isGitHubSSOSession = (): boolean => {
  // You can store this flag during GitHub login
  return localStorage.getItem('auth_provider') === 'github';
};

/**
 * Set authentication provider (call this after successful GitHub login)
 */
export const setAuthProvider = (provider: 'local' | 'github'): void => {
  localStorage.setItem('auth_provider', provider);
};

/**
 * Clear authentication provider on logout
 */
export const clearAuthProvider = (): void => {
  localStorage.removeItem('auth_provider');
};

// Export existing api instance as default
export default api;
