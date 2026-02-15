import { useCallback, useEffect, useState } from 'react';
import { Lock, KeyRound, ShieldCheck, AlertCircle, Eye, EyeOff } from 'lucide-react';
import { db } from './db/db';
import { deriveKey, decrypt, encrypt, generateSalt } from './services/SecurityService';

type Screen = 'loading' | 'setup' | 'unlock' | 'unlocked';

function App() {
  const [screen, setScreen] = useState<Screen>('loading');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  // ── On mount: decide if the DB already has an identity ──────────────────────
  useEffect(() => {
    (async () => {
      try {
        const identity = await db.identity.get('self');
        setScreen(identity ? 'unlock' : 'setup');
      } catch {
        setScreen('setup');
      }
    })();
  }, []);

  // ── Setup: create a new local password & persist a verification marker ──────
  const handleSetup = useCallback(async () => {
    setError('');

    if (password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }
    if (password !== confirmPassword) {
      setError('Passwords do not match.');
      return;
    }

    setBusy(true);
    try {
      const salt = generateSalt();
      const key = await deriveKey(password, salt);

      // Encrypt a known verification token so we can later verify the password.
      const verificationToken = 'tenebra-verified';
      const { cipherText, iv } = await encrypt(verificationToken, key);

      // Persist the salt and verification ciphertext in the meta table.
      await db.meta.bulkPut([
        { key: 'salt', value: salt },
        { key: 'verification', value: JSON.stringify({ cipherText, iv }) },
      ]);

      // Store a placeholder identity row so subsequent loads show "unlock".
      await db.identity.put({
        id: 'self',
        registrationId: 0,
        publicKey: '',
        encryptedPrivateKey: '',
        encryptedPrivateKeyIv: '',
      });

      setScreen('unlocked');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Setup failed.');
    } finally {
      setBusy(false);
    }
  }, [password, confirmPassword]);

  // ── Unlock: verify the password against the stored marker ────────────────────
  const handleUnlock = useCallback(async () => {
    setError('');
    setBusy(true);

    try {
      const saltRow = await db.meta.get('salt');
      const verificationRow = await db.meta.get('verification');

      if (!saltRow || !verificationRow) {
        setError('Database is corrupted. Please clear data and set up again.');
        return;
      }

      const key = await deriveKey(password, saltRow.value);
      const { cipherText, iv } = JSON.parse(verificationRow.value);

      // Attempt decryption — if the password is wrong AES-GCM will throw.
      const result = await decrypt(cipherText, iv, key);

      if (result !== 'tenebra-verified') {
        setError('Incorrect password.');
        return;
      }

      setScreen('unlocked');
    } catch {
      setError('Incorrect password.');
    } finally {
      setBusy(false);
    }
  }, [password]);

  // ── Render ────────────────────────────────────────────────────────────────────

  if (screen === 'loading') {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gray-950">
        <Lock className="h-8 w-8 animate-pulse text-indigo-400" />
      </div>
    );
  }

  if (screen === 'unlocked') {
    return (
      <div className="flex min-h-screen flex-col items-center justify-center gap-4 bg-gray-950">
        <ShieldCheck className="h-16 w-16 text-emerald-400" />
        <h1 className="text-2xl font-semibold text-gray-100">Vault Unlocked</h1>
        <p className="text-sm text-gray-400">
          Your encrypted database is ready. Next stages will render the chat UI here.
        </p>
      </div>
    );
  }

  const isSetup = screen === 'setup';

  return (
    <div className="flex min-h-screen items-center justify-center bg-gray-950 p-4">
      <div className="w-full max-w-sm rounded-2xl border border-gray-800 bg-gray-900 p-8 shadow-xl">
        {/* Header */}
        <div className="mb-6 flex flex-col items-center gap-3">
          <div className="flex h-14 w-14 items-center justify-center rounded-full bg-indigo-500/10">
            {isSetup ? (
              <KeyRound className="h-7 w-7 text-indigo-400" />
            ) : (
              <Lock className="h-7 w-7 text-indigo-400" />
            )}
          </div>
          <h1 className="text-xl font-bold text-gray-100">
            {isSetup ? 'Create Local Password' : 'Unlock Vault'}
          </h1>
          <p className="text-center text-sm text-gray-400">
            {isSetup
              ? 'This password encrypts your private keys locally. It never leaves your device.'
              : 'Enter your local password to decrypt your keys.'}
          </p>
        </div>

        {/* Form */}
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (isSetup) {
              handleSetup();
            } else {
              handleUnlock();
            }
          }}
          className="flex flex-col gap-4"
        >
          {/* Password field */}
          <div className="relative">
            <input
              type={showPassword ? 'text' : 'password'}
              placeholder="Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2.5 pr-10 text-sm text-gray-100 placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
              autoFocus
            />
            <button
              type="button"
              onClick={() => setShowPassword((v) => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
              tabIndex={-1}
            >
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>

          {/* Confirm password (setup only) */}
          {isSetup && (
            <input
              type={showPassword ? 'text' : 'password'}
              placeholder="Confirm password"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              className="w-full rounded-lg border border-gray-700 bg-gray-800 px-4 py-2.5 text-sm text-gray-100 placeholder-gray-500 outline-none transition focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500"
            />
          )}

          {/* Error */}
          {error && (
            <div className="flex items-center gap-2 rounded-lg bg-red-500/10 px-3 py-2 text-sm text-red-400">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{error}</span>
            </div>
          )}

          {/* Submit */}
          <button
            type="submit"
            disabled={busy}
            className="mt-1 w-full rounded-lg bg-indigo-600 py-2.5 text-sm font-medium text-white transition hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {busy ? 'Working…' : isSetup ? 'Create Password' : 'Unlock'}
          </button>
        </form>
      </div>
    </div>
  );
}

export default App;

