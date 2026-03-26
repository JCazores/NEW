import { create } from 'zustand';

const stored = JSON.parse(localStorage.getItem('periodStore') || '{}');

export const usePeriodStore = create((set) => ({
  incidentPeriod: stored.incidentPeriod || 'hour',
  causePeriod:    stored.causePeriod    || 'hour',
  userPeriod:     stored.userPeriod     || 'hour',
  monitorPeriod:  stored.monitorPeriod  || 'hour',
  exportPeriod:   stored.exportPeriod   || 'hour',

  setPeriod: (key, value) => {
    const updated = JSON.parse(localStorage.getItem('periodStore') || '{}');
    updated[key] = value;
    localStorage.setItem('periodStore', JSON.stringify(updated));
    set({ [key]: value });
  },
}));