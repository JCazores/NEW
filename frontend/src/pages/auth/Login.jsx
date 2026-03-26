import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Eye, EyeOff, AlertTriangle, ShieldOff, Lock } from 'lucide-react';
import { login } from '../../api/authApi';
import { useAuthStore } from '../../store/authStore';
import Logo from '../../components/shared/Logo';

const MAX_ATTEMPTS = 5;

function pickLaravelError(err, fallback = 'Something went wrong') {
  const data = err?.response?.data;
  if (data?.errors && typeof data.errors === 'object') {
    const firstField = Object.keys(data.errors)[0];
    const firstMsg   = data.errors[firstField]?.[0];
    if (firstMsg) return firstMsg;
  }
  return data?.message || fallback;
}

// Countdown timer display
function LockoutTimer({ seconds, onExpire }) {
  const [remaining, setRemaining] = useState(seconds);

  useState(() => {
    if (remaining <= 0) { onExpire(); return; }
    const t = setInterval(() => {
      setRemaining(prev => {
        if (prev <= 1) { clearInterval(t); onExpire(); return 0; }
        return prev - 1;
      });
    }, 1000);
    return () => clearInterval(t);
  }, []);

  const mins = Math.floor(remaining / 60);
  const secs = remaining % 60;
  return (
    <span className="font-mono font-bold text-red-400">
      {mins > 0 ? `${mins}m ` : ''}{secs}s
    </span>
  );
}

// Attempt dots indicator
function AttemptDots({ attemptsLeft }) {
  return (
    <div className="flex items-center justify-center gap-1.5 my-1">
      {Array.from({ length: MAX_ATTEMPTS }).map((_, i) => (
        <div
          key={i}
          className={`w-2.5 h-2.5 rounded-full transition-all duration-300
            ${i < attemptsLeft
              ? attemptsLeft <= 2 ? 'bg-red-400' : attemptsLeft === 3 ? 'bg-yellow-400' : 'bg-green-400'
              : 'bg-gray-700'
            }`}
        />
      ))}
    </div>
  );
}

export default function Login() {
  const navigate = useNavigate();
  const setAuth  = useAuthStore(s => s.setAuth);

  const [loading, setLoading]               = useState(false);
  const [showPasswordField, setShowPasswordField] = useState(false);
  const [showPassword, setShowPassword]     = useState(false);
  const [email, setEmail]                   = useState('');
  const [password, setPassword]             = useState('');

  // Attempt tracking
  const [attemptsLeft, setAttemptsLeft]     = useState(MAX_ATTEMPTS);
  const [lockedOut, setLockedOut]           = useState(false);
  const [lockoutSeconds, setLockoutSeconds] = useState(0);

  const handleLockedOut = (seconds) => {
    setLockedOut(true);
    setAttemptsLeft(0);
    setLockoutSeconds(seconds ?? 300);
  };

  const handleFailedAttempt = (responseData) => {
    const left = responseData?.attempts_left ?? (attemptsLeft - 1);
    setAttemptsLeft(left);
    if (responseData?.locked_out || left <= 0) {
      handleLockedOut(responseData?.available_in ?? 300);
    }
  };

  const checkEmail = async () => {
    if (!email || !email.includes('@')) {
      toast.error('Please enter a valid email');
      return;
    }
    setLoading(true);
    try {
      const res = await login({ email });

      if (res.data.requires_otp) {
        toast.success(res.data.message || 'OTP sent to your email');
        navigate('/verify-otp', { state: { email } });
        return;
      }

      if (res.data.token && res.data.user) {
        setAuth(res.data.user, res.data.token);
        toast.success('Welcome back!');
        navigate(res.data.user.role === 'admin' ? '/admin/dashboard' : '/user/dashboard');
        return;
      }

      setShowPasswordField(true);
    } catch (err) {
      const status = err?.response?.status;
      const data   = err?.response?.data;
      const msg    = pickLaravelError(err, 'Login failed');

      if (status === 429) { handleLockedOut(data?.available_in); return; }
      if (status === 422 && /password required/i.test(msg)) { setShowPasswordField(true); return; }
      if (status === 403) { toast.error(msg); return; }

      if (status === 404) {
        handleFailedAttempt(data);
        toast.error('Email not found. Please contact administrator.');
        return;
      }

      handleFailedAttempt(data);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const onSubmitWithPassword = async (e) => {
    e.preventDefault();
    if (!password) { toast.error('Please enter your password'); return; }

    setLoading(true);
    try {
      const res = await login({ email, password });

      if (res.data.requires_otp) {
        toast.success(res.data.message || 'OTP sent to your email');
        navigate('/verify-otp', { state: { email } });
        return;
      }

      setAuth(res.data.user, res.data.token);
      toast.success('Welcome back!');
      navigate(res.data.user.role === 'admin' ? '/admin/dashboard' : '/user/dashboard');
    } catch (err) {
      const status = err?.response?.status;
      const data   = err?.response?.data;
      const msg    = pickLaravelError(err, 'Invalid credentials');

      if (status === 429) { handleLockedOut(data?.available_in); return; }

      handleFailedAttempt(data);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const backToEmail = () => {
    setShowPasswordField(false);
    setPassword('');
    setShowPassword(false);
  };

  // ── Locked out screen ────────────────────────────────────────────────────
  if (lockedOut) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-950">
        <div className="bg-gray-900 p-8 rounded-2xl w-full max-w-md shadow-2xl border border-red-500/30 text-center">
          <div className="flex justify-center mb-5">
            <div className="w-16 h-16 rounded-full bg-red-500/10 border border-red-500/30 flex items-center justify-center">
              <ShieldOff size={30} className="text-red-400" />
            </div>
          </div>
          <h2 className="text-white text-xl font-bold mb-2">Account Temporarily Locked</h2>
          <p className="text-gray-400 text-sm mb-4">
            Too many failed login attempts. Please wait before trying again.
          </p>
          <div className="bg-gray-800 rounded-xl px-6 py-4 mb-6 inline-block">
            <p className="text-gray-500 text-xs mb-1">Try again in</p>
            <LockoutTimer
              seconds={lockoutSeconds}
              onExpire={() => {
                setLockedOut(false);
                setAttemptsLeft(MAX_ATTEMPTS);
                setPassword('');
              }}
            />
          </div>
          <p className="text-gray-600 text-xs">
            If you believe this is a mistake, please contact your administrator.
          </p>
        </div>
      </div>
    );
  }

  // ── Normal login ─────────────────────────────────────────────────────────
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <div className="bg-gray-900 p-8 rounded-2xl w-full max-w-md shadow-2xl border border-gray-800">
        <div className="flex flex-col items-center gap-3 mb-6">
          <Logo size="large" />
          <h1 className="text-white text-2xl font-bold">ServerSentinel</h1>
        </div>

        <h2 className="text-gray-300 text-lg mb-6">Sign in</h2>

        {!showPasswordField ? (
          <form onSubmit={(e) => { e.preventDefault(); checkEmail(); }} className="space-y-4">
            <div>
              <label className="text-gray-400 text-sm">Email</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                placeholder="your.email@gmail.com"
                className="w-full mt-1 px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
              />
            </div>

            {/* Attempts warning */}
            {attemptsLeft < MAX_ATTEMPTS && (
              <div className={`rounded-xl p-3 border text-center
                ${attemptsLeft <= 2
                  ? 'bg-red-500/10 border-red-500/30'
                  : 'bg-yellow-500/10 border-yellow-500/30'
                }`}
              >
                <AttemptDots attemptsLeft={attemptsLeft} />
                <p className={`text-xs mt-1 font-medium flex items-center justify-center gap-1
                  ${attemptsLeft <= 2 ? 'text-red-400' : 'text-yellow-400'}`}
                >
                  <AlertTriangle size={13} />
                  {attemptsLeft} attempt{attemptsLeft !== 1 ? 's' : ''} remaining before lockout
                </p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2 bg-green-500 hover:bg-green-400 text-black font-semibold rounded-lg transition disabled:opacity-50"
            >
              {loading ? 'Checking...' : 'Continue'}
            </button>
          </form>
        ) : (
          <form onSubmit={onSubmitWithPassword} className="space-y-4">
            <div>
              <label className="text-gray-400 text-sm">Email</label>
              <input
                type="email"
                value={email}
                readOnly
                className="w-full mt-1 px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 outline-none opacity-75"
              />
            </div>

            <div>
              <label className="text-gray-400 text-sm">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                  autoFocus
                  className="w-full mt-1 px-4 py-2 pr-12 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition"
                >
                  {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
                </button>
              </div>
            </div>

            {/* Attempts warning */}
            {attemptsLeft < MAX_ATTEMPTS && (
              <div className={`rounded-xl p-3 border text-center
                ${attemptsLeft <= 2
                  ? 'bg-red-500/10 border-red-500/30'
                  : 'bg-yellow-500/10 border-yellow-500/30'
                }`}
              >
                <AttemptDots attemptsLeft={attemptsLeft} />
                <p className={`text-xs mt-1 font-medium flex items-center justify-center gap-1
                  ${attemptsLeft <= 2 ? 'text-red-400' : 'text-yellow-400'}`}
                >
                  <AlertTriangle size={13} />
                  {attemptsLeft} attempt{attemptsLeft !== 1 ? 's' : ''} remaining before lockout
                </p>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className="w-full py-2 bg-green-500 hover:bg-green-400 text-black font-semibold rounded-lg transition disabled:opacity-50"
            >
              {loading ? 'Signing in...' : 'Login'}
            </button>

            <button
              type="button"
              onClick={backToEmail}
              className="w-full text-sm text-gray-400 hover:text-green-400 transition"
            >
              ← Back to email
            </button>
          </form>
        )}

        <div className="mt-6 text-center text-gray-500 text-sm">
          <p>First time? Enter email to receive OTP</p>
          <p className="mt-1">Already registered? Use your password</p>
        </div>
      </div>
    </div>
  );
}