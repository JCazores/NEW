import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useForm } from 'react-hook-form';
import toast from 'react-hot-toast';
import api from '../../api/axios';
import Logo from '../../components/shared/Logo';

export default function Register() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const { register, handleSubmit } = useForm();

  const onSubmit = async (data) => {
    setLoading(true);
    try {
      const res = await api.post('/auth/register', data);
      toast.success('OTP sent to your email!');
      navigate('/verify-otp', { state: { email: data.email } });
    } catch (err) {
      toast.error(err.response?.data?.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-950">
      <div className="bg-gray-900 p-8 rounded-2xl w-full max-w-md shadow-2xl border border-gray-800">
        <div className="flex items-center gap-3 mb-6">
          <logo size="large" />
          <h1 className="text-white text-2xl font-bold">ServerSentinel</h1>
        </div>
        <h2 className="text-gray-300 text-lg mb-2">Create Account</h2>
        <p className="text-gray-500 text-sm mb-6">Enter your Gmail to get started</p>

        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <div>
            <label className="text-gray-400 text-sm">Gmail Address</label>
            <input 
              {...register('email')} 
              type="email" 
              required
              pattern=".*@gmail\.com$"
              title="Must be a Gmail address"
              placeholder="your.email@gmail.com"
              className="w-full mt-1 px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-700 focus:border-green-500 outline-none" 
            />
          </div>
          
          <button 
            type="submit" 
            disabled={loading}
            className="w-full py-2 bg-green-500 hover:bg-green-400 text-black font-semibold rounded-lg transition disabled:opacity-50"
          >
            {loading ? 'Sending OTP...' : 'Continue'}
          </button>
        </form>

        <div className="mt-6 text-center">
          <Link to="/login" className="text-sm text-gray-400 hover:text-green-400 transition">
            Already have an account? <span className="font-semibold">Login</span>
          </Link>
        </div>
      </div>
    </div>
  );
}