/**
 * AuthScreen — Register / Login UI for Tenebra Web.
 *
 * Receives the unlocked AES CryptoKey from App.tsx and wires it into
 * the AuthService register / login flows.
 */

import { useCallback, useState } from 'react';
import { UserPlus, LogIn, AlertCircle, Loader2, Ticket } from 'lucide-react';
import { register, login, type AuthResult } from '@/services/AuthService';

interface AuthScreenProps {
  /** AES-GCM CryptoKey derived from the user's local password. */
  encryptionKey: CryptoKey;
  /** Called after a successful register or login. */
  onAuthenticated: (result: AuthResult) => void;
}

export default function AuthScreen({ encryptionKey, onAuthenticated }: AuthScreenProps) {
  const [mode, setMode] = useState<'register' | 'login'>('register');
  const [username, setUsername] = useState('');
  const [inviteCode, setInviteCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const handleSubmit = useCallback(async () => {
    setError('');
    const trimmed = username.trim();

    if (!trimmed) {
      setError('Please enter a username.');
      return;
    }
    if (trimmed.length < 3) {
      setError('Username must be at least 3 characters.');
      return;
    }

    setBusy(true);
    try {
      const result =
        mode === 'register'
          ? await register(trimmed, encryptionKey, inviteCode.trim())
          : await login(trimmed, encryptionKey);

      onAuthenticated(result);
    } catch (err: unknown) {
      // Surface the backend error message when available
      if (
        typeof err === 'object' &&
        err !== null &&
        'response' in err &&
        typeof (err as Record<string, unknown>).response === 'object'
      ) {
        const resp = (err as { response: { data?: { error?: string } } }).response;
        setError(resp.data?.error ?? 'Request failed.');
      } else if (err instanceof Error) {
        setError(err.message);
      } else {
        setError('An unexpected error occurred.');
      }
    } finally {
      setBusy(false);
    }
  }, [mode, username, inviteCode, encryptionKey, onAuthenticated]);

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 p-4">
      <div className="w-full max-w-sm rounded-2xl border border-gray-800 bg-gray-900 p-8 shadow-xl">
        {/* Header */}
        <div className="mb-6 flex flex-col items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-indigo-500/10">
            {mode === 'register' ? (
              <UserPlus className="h-7 w-7 text-indigo-400" />
            ) : (
              <LogIn className="h-7 w-7 text-indigo-400" />
            )}
          </div>
          <h1 className="text-xl font-bold text-gray-100">
            {mode === 'register' ? 'Create Account' : 'Welcome Back'}
          </h1>
          <p className="text-center text-sm text-gray-400">
            {mode === 'register'
              ? 'Register a new account with an invite code.'
              : 'Log in with your existing identity.'}
          </p>
        </div>

        {/* Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            handleSubmit();
          }}
          className="flex flex-col gap-4"
        >
          <label htmlFor="username-input" className="sr-only">
            Username
          </label>
          <input
            id="username-input"
            type="text"
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2.5 text-sm text-gray-100 placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
            autoFocus
            disabled={busy}
          />

          {mode === 'register' && (
            <>
              <label htmlFor="invite-code-input" className="sr-only">
                Invite Code
              </label>
              <div className="relative">
                <Ticket className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-gray-500" />
                <input
                  id="invite-code-input"
                  type="text"
                  placeholder="Invite Code"
                  value={inviteCode}
                  onChange={(e) => setInviteCode(e.target.value)}
                  className="w-full rounded-lg border border-gray-700 bg-gray-800 py-2.5 pl-10 pr-4 text-sm text-gray-100 placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
                  disabled={busy}
                />
              </div>
            </>
          )}

          {/* Error */}
          {error && (
            <div className="flex items-center gap-2 rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Submit button */}
          <button
            type="submit"
            disabled={busy}
            className="flex w-full items-center justify-center gap-2 rounded-lg bg-indigo-600 py-2.5 text-sm font-medium text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : mode === 'register' ? (
              <UserPlus className="h-4 w-4" />
            ) : (
              <LogIn className="h-4 w-4" />
            )}
            {mode === 'register' ? 'Register' : 'Login'}
          </button>

          {/* Toggle mode */}
          <p className="text-center text-sm text-gray-500">
            {mode === 'register' ? 'Already have an account?' : "Don't have an account?"}{' '}
            <button
              type="button"
              disabled={busy}
              onClick={() => {
                setMode(mode === 'register' ? 'login' : 'register');
                setError('');
              }}
              className="font-medium text-indigo-400 hover:text-indigo-300 disabled:opacity-50"
            >
              {mode === 'register' ? 'Login' : 'Register'}
            </button>
          </p>
        </form>
      </div>
    </div>
  );
}
