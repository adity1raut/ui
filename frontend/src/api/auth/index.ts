import { api } from '../../lib/api';
import { LoginDetails, LoginResponse, VerifyTokenResponse } from './types';

export const LoginUser = async (data: LoginDetails): Promise<LoginResponse> => {
  const response = await api.post<LoginResponse>('/login', data);
  return response.data;
};

export const VerifyToken = async (token: string): Promise<VerifyTokenResponse> => {
  const response = await api.get<VerifyTokenResponse>('/api/me', {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });
  return response.data;
};

/**
 * Initiates GitHub OAuth flow by redirecting to backend OAuth endpoint
 */
export const initiateGitHubLogin = (): void => {
  const baseUrl = import.meta.env.VITE_BASE_URL;
  window.location.href = `${baseUrl}/auth/github`;
};

/**
 * Handles GitHub OAuth callback by extracting tokens from URL
 * Returns parsed tokens and user info if available
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
      // Clean up URL by removing query parameters
      window.history.replaceState({}, document.title, window.location.pathname);

      return { success: true, accessToken, refreshToken };
    }

    return { success: false, error: 'No tokens received from OAuth callback' };
  } catch (error) {
    console.error('Error handling GitHub callback:', error);
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error occurred',
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
      return { success: true, accessToken: access_token, refreshToken: refresh_token, user };
    }

    return { success: false, error: 'Invalid response from server' };
  } catch (error) {
    console.error('GitHub code exchange failed:', error);
    if (error instanceof Error) {
      return {
        success: false,
        error: error.message || 'Failed to authenticate with GitHub',
      };
    }
    return { success: false, error: 'Unknown error occurred' };
  }
};

/**
 * Check if user is authenticated via any method (local or GitHub)
 * Returns user info if authenticated
 */
export const checkAuth = async (): Promise<VerifyTokenResponse> => {
  const response = await api.get<VerifyTokenResponse>('/api/me');
  return response.data;
};
