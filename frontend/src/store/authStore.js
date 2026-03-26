import { create } from 'zustand';

export const useAuthStore = create((set, get) => ({
  user: null,
  token: localStorage.getItem('token'),
  isLoading: true,

  setAuth: (user, token) => {
    localStorage.setItem('token', token);
    set({ user, token, isLoading: false });
  },

  updateUser: (user) => set({ user }), // ← ADD THIS LINE

  clearAuth: () => {
    localStorage.removeItem('token');
    set({ user: null, token: null, isLoading: false });
  },

  setLoading: (val) => set({ isLoading: val }),

  isAdmin: () => get().user?.role === 'admin',
}));