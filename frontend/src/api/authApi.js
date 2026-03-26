import api from './axios';

// Auth endpoints
export const login = (data) => api.post('/login', data);
export const verifyOtp = (data) => api.post('/verify-otp', data);
export const resendOtp = (data) => api.post('/resend-otp', data);

export const logout = () => api.post('/logout');

// "me" endpoint in your routes is GET /user
export const getMe = () => api.get('/user');