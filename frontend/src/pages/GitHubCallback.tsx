import { useEffect } from 'react';
import { useGitHubLogin } from '../hooks/queries/useLogin';
import { useTranslation } from 'react-i18next';

/**
 * GitHub OAuth Callback Page
 * This page handles the redirect from GitHub after OAuth authorization
 */
export const GitHubCallback = () => {
  const { t } = useTranslation();
  const { handleCallback, isLoading } = useGitHubLogin();

  useEffect(() => {
    // Automatically handle the callback when component mounts
    handleCallback();
  }, [handleCallback]);

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="text-center">
        {isLoading ? (
          <>
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto mb-4"></div>
            <h2 className="text-xl font-semibold text-gray-700">
              {t('auth.login.processingGitHub', {
                defaultValue: 'Processing GitHub authentication...',
              })}
            </h2>
            <p className="text-gray-500 mt-2">
              {t('auth.login.pleaseWait', { defaultValue: 'Please wait...' })}
            </p>
          </>
        ) : (
          <>
            <h2 className="text-xl font-semibold text-gray-700">
              {t('auth.login.redirecting', { defaultValue: 'Redirecting...' })}
            </h2>
          </>
        )}
      </div>
    </div>
  );
};