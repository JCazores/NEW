import api from './axios';

// Users
export const getUsers          = ()         => api.get('/admin/users');
export const createUser        = (data)     => api.post('/admin/users', data);
export const deleteUser        = (id)       => api.delete(`/admin/users/${id}`);
export const updateStatus      = (id, data) => api.patch(`/admin/users/${id}/status`, data);
export const resendOtp         = (data)     => api.post('/admin/users/resend-otp', data);

// ─── NEW: Permissions ──────────────────────────────────────────────────────────
export const updatePermissions = (id, permissions) =>
  api.patch(`/admin/users/${id}/permissions`, { permissions });

// Monitors
export const getAdminMonitors  = ()         => api.get('/admin/monitors');
export const createMonitor     = (data)     => api.post('/admin/monitors', data);
export const updateMonitor     = (id, data) => api.put(`/admin/monitors/${id}`, data);
export const deleteMonitor     = (id)       => api.delete(`/admin/monitors/${id}`);
export const toggleMonitor     = (id)       => api.post(`/admin/monitors/${id}/toggle`);
export const getMonitorUsers   = ()         => api.get('/admin/monitors/users');

// Incidents
export const getIncidents             = (params)           => api.get('/admin/incidents', { params });
export const getIncidentStats         = ()                  => api.get('/admin/incidents/stats');
export const updateIncidentRootCause  = (id, rootCause)    =>
  api.patch(`/admin/incidents/${id}/root-cause`, { root_cause: rootCause });

// Dashboard
export const getDashboardStats = () => api.get('/admin/dashboard');

// Categories
export const getCategories   = ()     => api.get('/admin/categories');
export const createCategory  = (data) => api.post('/admin/categories', data);
export const deleteCategory  = (id)   => api.delete(`/admin/categories/${id}`);