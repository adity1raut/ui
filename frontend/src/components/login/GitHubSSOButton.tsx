import { useEffect } from 'react';
import { motion } from 'framer-motion';
import { useGitHubLogin } from '../../hooks/queries/useLogin';
import { useTranslation } from 'react-i18next';
import { FaGithub } from 'react-icons/fa';

interface GitHubSSOButtonProps {
  fullWidth?: boolean;
  disabled?: boolean;
  className?: string;
}

export const GitHubSSOButton: React.FC<GitHubSSOButtonProps> = ({
  fullWidth = false,
  disabled = false,
  className = '',
}) => {
  const { t } = useTranslation();
  const { initiateLogin, handleCallback, isLoading } = useGitHubLogin();

  // Handle OAuth callback on component mount
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const hasToken = urlParams.get('token');
    const hasError = urlParams.get('error');

    // Only process callback if we have token or error parameters
    if (hasToken || hasError) {
      handleCallback();
    }
  }, [handleCallback]);

  return (
    <motion.button
      type="button"
      onClick={initiateLogin}
      disabled={disabled || isLoading}
      className={`
        relative flex transform items-center justify-center gap-3 overflow-hidden rounded-xl 
        bg-[#24292e] px-4 py-3.5 font-medium text-white shadow-lg 
        transition-all duration-300 
        hover:-translate-y-0.5 hover:bg-[#2c3137] hover:shadow-gray-800/25
        disabled:cursor-not-allowed disabled:opacity-50
        focus:outline-none focus:ring-2 focus:ring-gray-600 focus:ring-offset-2 focus:ring-offset-[#0f1419]
        ${fullWidth ? 'w-full' : ''}
        ${className}
      `}
      whileHover={{ scale: disabled || isLoading ? 1 : 1.02 }}
      whileTap={{ scale: disabled || isLoading ? 1 : 0.98 }}
      aria-label={t('login.form.continueWithGitHub', { defaultValue: 'Continue with GitHub' })}
    >
      {isLoading ? (
        <>
          <div className="h-5 w-5 animate-spin rounded-full border-2 border-white border-t-transparent"></div>
          <span>
            {t('login.form.authenticating', { defaultValue: 'Authenticating...' })}
          </span>
        </>
      ) : (
        <>
          <FaGithub className="text-xl" />
          <span>
            {t('login.form.continueWithGitHub', { defaultValue: 'Continue with GitHub' })}
          </span>
        </>
      )}
      <span className="absolute left-0 top-0 h-full w-full bg-gradient-to-r from-white/10 to-transparent opacity-0 transition-opacity duration-300 hover:opacity-100"></span>
    </motion.button>
  );
};