import { useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import toast from 'react-hot-toast';
import { Eye, EyeOff, Check, X } from 'lucide-react';
import api from '../../api/axios';
import { useAuthStore } from '../../store/authStore';
import Logo from '../../components/shared/Logo';

export default function VerifyOtp() {
  const { state } = useLocation();
  const navigate = useNavigate();
  const setAuth = useAuthStore(s => s.setAuth);
  const email = state?.email;

  const [otp, setOtp] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [resending, setResending] = useState(false);

  // Password strength validation
  const passwordRequirements = {
    minLength: password.length >= 8,
    hasUpperCase: /[A-Z]/.test(password),
    hasLowerCase: /[a-z]/.test(password),
    hasNumber: /[0-9]/.test(password),
    hasSpecialChar: /[!@#$%^&*(),.?":{}|<>]/.test(password),
  };

  const isPasswordStrong = Object.values(passwordRequirements).every(req => req);

  const handleVerify = async (e) => {
    e.preventDefault();

    if (!email) {
      toast.error('Missing email. Please go back to login and try again.');
      return;
    }

    // Check password strength
    if (!isPasswordStrong) {
      toast.error('Password does not meet security requirements');
      return;
    }

    if (password !== confirmPassword) {
      toast.error('Passwords do not match');
      return;
    }

    setLoading(true);
    try {
      // ✅ FIXED ENDPOINT: remove "/auth"
      const res = await api.post('/verify-otp', {
        email,
        otp,
        name,
        password,
        password_confirmation: confirmPassword,
      });

      setAuth(res.data.user, res.data.token);
      toast.success('Account setup complete!');
      navigate('/user/dashboard');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Invalid OTP');
    } finally {
      setLoading(false);
    }
  };

  const handleResend = async () => {
    if (!email) {
      toast.error('Missing email. Please go back to login and try again.');
      return;
    }

    setResending(true);
    try {
      // ✅ FIXED ENDPOINT: remove "/auth"
      await api.post('/resend-otp', { email });
      toast.success('OTP resent!');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to resend OTP');
    } finally {
      setResending(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950 p-4">
      <div className="bg-gray-900 p-8 rounded-2xl w-full max-w-md shadow-2xl border border-gray-800">
        <div className="flex flex-col items-center gap-3 mb-6">
          <Logo size="large" />
          <h1 className="text-white text-2xl font-bold">ServerSentinel</h1>
        </div>

        <h2 className="text-gray-300 text-lg mb-2">Complete Your Account</h2>
        <p className="text-gray-500 text-sm mb-6">
          Enter the OTP sent to <span className="text-green-400">{email}</span>
        </p>

        <form onSubmit={handleVerify} className="space-y-4">
          <div>
            <label className="text-gray-400 text-sm">OTP Code</label>
            <input
              value={otp}
              onChange={e => setOtp(e.target.value)}
              maxLength={6}
              placeholder="123456"
              required
              autoFocus
              className="w-full mt-1 px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none text-center text-2xl tracking-widest"
            />
          </div>

          <div>
            <label className="text-gray-400 text-sm">Your Name</label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              required
              placeholder="John Doe"
              className="w-full mt-1 px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none"
            />
          </div>

          <div>
            <label className="text-gray-400 text-sm">Create Strong Password</label>
            <div className="relative">
              <input
                type={showPassword ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                required
                placeholder="Enter strong password"
                className={`w-full mt-1 px-4 py-2 pr-12 bg-gray-800 text-white rounded-lg border ${
                  password && !isPasswordStrong
                    ? 'border-red-500 focus:border-red-500'
                    : 'border-gray-700 focus:border-green-500'
                } outline-none`}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition"
              >
                {showPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>

            {password && (
              <div className="mt-3 p-3 bg-gray-800/50 rounded-lg space-y-2">
                <p className="text-xs text-gray-400 font-semibold mb-2">Password must contain:</p>

                <div className="flex items-center gap-2 text-xs">
                  {passwordRequirements.minLength ? (
                    <Check size={16} className="text-green-400" />
                  ) : (
                    <X size={16} className="text-red-400" />
                  )}
                  <span className={passwordRequirements.minLength ? 'text-green-400' : 'text-gray-400'}>
                    At least 8 characters
                  </span>
                </div>

                <div className="flex items-center gap-2 text-xs">
                  {passwordRequirements.hasUpperCase ? (
                    <Check size={16} className="text-green-400" />
                  ) : (
                    <X size={16} className="text-red-400" />
                  )}
                  <span className={passwordRequirements.hasUpperCase ? 'text-green-400' : 'text-gray-400'}>
                    One uppercase letter (A-Z)
                  </span>
                </div>

                <div className="flex items-center gap-2 text-xs">
                  {passwordRequirements.hasLowerCase ? (
                    <Check size={16} className="text-green-400" />
                  ) : (
                    <X size={16} className="text-red-400" />
                  )}
                  <span className={passwordRequirements.hasLowerCase ? 'text-green-400' : 'text-gray-400'}>
                    One lowercase letter (a-z)
                  </span>
                </div>

                <div className="flex items-center gap-2 text-xs">
                  {passwordRequirements.hasNumber ? (
                    <Check size={16} className="text-green-400" />
                  ) : (
                    <X size={16} className="text-red-400" />
                  )}
                  <span className={passwordRequirements.hasNumber ? 'text-green-400' : 'text-gray-400'}>
                    One number (0-9)
                  </span>
                </div>

                <div className="flex items-center gap-2 text-xs">
                  {passwordRequirements.hasSpecialChar ? (
                    <Check size={16} className="text-green-400" />
                  ) : (
                    <X size={16} className="text-red-400" />
                  )}
                  <span className={passwordRequirements.hasSpecialChar ? 'text-green-400' : 'text-gray-400'}>
                    One special character (!@#$%^&*)
                  </span>
                </div>

                {isPasswordStrong && (
                  <div className="pt-2 mt-2 border-t border-gray-700">
                    <p className="text-green-400 text-xs font-semibold flex items-center gap-2">
                      <Check size={16} />
                      Password is strong! ✓
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>

          <div>
            <label className="text-gray-400 text-sm">Confirm Password</label>
            <div className="relative">
              <input
                type={showConfirmPassword ? 'text' : 'password'}
                value={confirmPassword}
                onChange={e => setConfirmPassword(e.target.value)}
                required
                placeholder="Repeat password"
                className={`w-full mt-1 px-4 py-2 pr-12 bg-gray-800 text-white rounded-lg border ${
                  confirmPassword && password !== confirmPassword
                    ? 'border-red-500 focus:border-red-500'
                    : 'border-gray-700 focus:border-green-500'
                } outline-none`}
              />
              <button
                type="button"
                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-white transition"
              >
                {showConfirmPassword ? <EyeOff size={20} /> : <Eye size={20} />}
              </button>
            </div>

            {confirmPassword && password !== confirmPassword && (
              <p className="text-red-400 text-xs mt-2 flex items-center gap-1">
                <X size={14} />
                Passwords do not match
              </p>
            )}
            {confirmPassword && password === confirmPassword && (
              <p className="text-green-400 text-xs mt-2 flex items-center gap-1">
                <Check size={14} />
                Passwords match
              </p>
            )}
          </div>

          <button
            type="submit"
            disabled={loading || !isPasswordStrong || password !== confirmPassword}
            className="w-full py-2 bg-green-500 hover:bg-green-400 text-black font-semibold rounded-lg transition disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Setting up...' : 'Complete Setup'}
          </button>

          {!isPasswordStrong && password && (
            <p className="text-red-400 text-xs text-center">
              Please create a strong password to continue
            </p>
          )}

          <button
            type="button"
            onClick={handleResend}
            disabled={resending}
            className="w-full text-sm text-gray-400 hover:text-green-400 transition"
          >
            {resending ? 'Sending...' : 'Resend OTP'}
          </button>
        </form>

        <div className="mt-6 text-center">
          <button
            onClick={() => navigate('/login')}
            className="text-sm text-gray-400 hover:text-green-400 transition"
          >
            ← Back to login
          </button>
        </div>
      </div>
    </div>
  );
}