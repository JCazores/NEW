import api from './axios';

// Dashboard
export const getUserDashboard = () => api.get('/user/dashboard');

// Monitors
export const getUserMonitors = () => api.get('/user/monitors');
export const createUserMonitor = (data) => api.post('/user/monitors', data);
export const deleteUserMonitor = (id) => api.delete(`/user/monitors/${id}`);

// Incidents
export const getUserIncidents = (params) => api.get('/user/incidents', { params });

// Stats for charts
export const getMonitorStats = (period) => api.get(`/user/monitor-stats?period=${period}`);
export const getIncidentStats = (period) => api.get(`/user/incident-stats?period=${period}`);
export const getIncidentsByCause = (period) => api.get(`/user/incidents-by-cause?period=${period}`);
export const exportIncidentsPdf = (period) => api.get(`/user/export-incidents-pdf?period=${period}`);

export const getCategories = () => api.get('/categories');