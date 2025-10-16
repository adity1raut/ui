// Token and refresh logic moved from src/lib/api.ts
import { AxiosInstance } from 'axios';
import { jwtDecode } from 'jwt-decode';

const REFRESH_ENDPOINT = import.meta.env.VITE_REFRESH_ENDPOINT || '/api/refresh';
const ACCESS_TOKEN_KEY = 'jwtToken';
const REFRESH_TOKEN_KEY = 'refreshToken';
const AUTH_PROVIDER_KEY = 'auth_provider';

export function getAccessToken() {
  return localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function setAccessToken(token: string) {
  localStorage.setItem(ACCESS_TOKEN_KEY, token);
}

export function getRefreshToken() {
  return localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setRefreshToken(token: string) {
  localStorage.setItem(REFRESH_TOKEN_KEY, token);
}

/**
 * Set both access and refresh tokens (useful for GitHub SSO callback)
 */
export function setTokens(accessToken: string, refreshToken: string) {
  setAccessToken(accessToken);
  setRefreshToken(refreshToken);
}

export function clearTokens() {
  localStorage.removeItem(ACCESS_TOKEN_KEY);
  localStorage.removeItem(REFRESH_TOKEN_KEY);
  localStorage.removeItem(AUTH_PROVIDER_KEY);
}

/**
 * Get the authentication provider (local or github)
 */
export function getAuthProvider(): 'local' | 'github' | null {
  return localStorage.getItem(AUTH_PROVIDER_KEY) as 'local' | 'github' | null;
}

/**
 * Set the authentication provider
 */
export function setAuthProvider(provider: 'local' | 'github') {
  localStorage.setItem(AUTH_PROVIDER_KEY, provider);
}

/**
 * Check if current session is from GitHub SSO
 */
export function isGitHubSSOSession(): boolean {
  return getAuthProvider() === 'github';
}

/**
 * Check if current session is from local login
 */
export function isLocalSession(): boolean {
  return getAuthProvider() === 'local';
}

interface JwtPayload {
  exp?: number;
  username?: string;
  userId?: number;
  isAdmin?: boolean;
  [key: string]: unknown;
}

export function isTokenExpired(token: string | null): boolean {
  if (!token) return true;
  try {
    const decoded = jwtDecode<JwtPayload>(token);
    if (!decoded.exp) return true;
    return Date.now() >= decoded.exp * 1000;
  } catch {
    return true;
  }
}

/**
 * Decode JWT token to get user information
 */
export function decodeToken(token: string | null): JwtPayload | null {
  if (!token) return null;
  try {
    return jwtDecode<JwtPayload>(token);
  } catch {
    return null;
  }
}

/**
 * Get user info from current access token
 */
export function getUserFromToken(): JwtPayload | null {
  const token = getAccessToken();
  return decodeToken(token);
}

let isRefreshing = false;
let refreshPromise: Promise<string | null> | null = null;

export async function refreshAccessToken(api: AxiosInstance): Promise<string | null> {
  if (isRefreshing && refreshPromise) return refreshPromise;
  isRefreshing = true;
  const refreshToken = getRefreshToken();
  if (!refreshToken) {
    isRefreshing = false;
    return null;
  }
  refreshPromise = api
    .post(REFRESH_ENDPOINT, { refreshToken })
    .then(res => {
      const { token, refreshToken: newRefreshToken } = res.data;
      if (token) setAccessToken(token);
      if (newRefreshToken) setRefreshToken(newRefreshToken);
      isRefreshing = false;
      refreshPromise = null;
      return token;
    })
    .catch(() => {
      isRefreshing = false;
      refreshPromise = null;
      clearTokens();
      return null;
    });
  return refreshPromise;
}

/**
 * Check if user is authenticated (has valid token)
 */
export function isAuthenticated(): boolean {
  const token = getAccessToken();
  return token !== null && !isTokenExpired(token);
}

/**
 * Get time remaining until token expires (in milliseconds)
 */
export function getTokenExpiryTime(token: string | null): number | null {
  if (!token) return null;
  try {
    const decoded = jwtDecode<JwtPayload>(token);
    if (!decoded.exp) return null;
    const expiryTime = decoded.exp * 1000;
    const timeRemaining = expiryTime - Date.now();
    return timeRemaining > 0 ? timeRemaining : 0;
  } catch {
    return null;
  }
}

/**
 * Setup automatic token refresh before expiry
 * @param api - Axios instance
 * @param refreshBeforeMinutes - Minutes before expiry to refresh (default: 5)
 * @returns Cleanup function to stop auto-refresh
 */
export function setupAutoTokenRefresh(
  api: AxiosInstance,
  refreshBeforeMinutes: number = 5
): () => void {
  let timeoutId: NodeJS.Timeout | null = null;

  const scheduleRefresh = () => {
    const token = getAccessToken();
    const timeRemaining = getTokenExpiryTime(token);

    if (timeRemaining === null) return;

    const refreshTime = timeRemaining - refreshBeforeMinutes * 60 * 1000;
    const refreshDelay = Math.max(0, refreshTime);

    timeoutId = setTimeout(async () => {
      await refreshAccessToken(api);
      scheduleRefresh(); // Schedule next refresh
    }, refreshDelay);
  };

  scheduleRefresh();

  // Return cleanup function
  return () => {
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
  };
}
