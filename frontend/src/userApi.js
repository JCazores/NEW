import api from './axios';

export const getUserMonitors = () => api.get('/user/monitors');
export const getUserMonitor = (id) => api.get(`/user/monitors/${id}`);
export const getUserIncidents = (params) => api.get('/user/incidents', { params });