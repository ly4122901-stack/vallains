import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

// Create axios instance with interceptors
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor to add auth token
apiClient.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('vallains_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// Response interceptor to handle 401 errors
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('vallains_token');
      // Only redirect if not already on login page
      if (!window.location.pathname.includes('/auth/')) {
        window.location.href = '/';
      }
    }
    return Promise.reject(error);
  }
);

// API methods
export const api = {
  // Auth methods
  login: async (email, password) => {
    const response = await apiClient.post('/auth/login', { email, password });
    return response.data;
  },

  register: async (name, email, password) => {
    const response = await apiClient.post('/auth/register', { name, email, password });
    return response.data;
  },

  getSession: async () => {
    const response = await apiClient.get('/auth/session');
    return response.data;
  },

  logout: async () => {
    const response = await apiClient.post('/auth/logout');
    return response.data;
  },

  logoutAll: async () => {
    const response = await apiClient.post('/auth/logout-all');
    return response.data;
  },

  // Scan methods
  scan: async (scanData) => {
    const response = await apiClient.post('/api/scan', scanData);
    return response.data;
  },

  getScanHistory: async (page = 1, limit = 20) => {
    const response = await apiClient.get('/api/scans', {
      params: { page, limit },
    });
    return response.data;
  },

  getScanById: async (scanId) => {
    const response = await apiClient.get(`/api/scans/${scanId}`);
    return response.data;
  },

  deleteScan: async (scanId) => {
    const response = await apiClient.delete(`/api/scans/${scanId}`);
    return response.data;
  },

  // Account methods
  getAccounts: async () => {
    const response = await apiClient.get('/api/accounts');
    return response.data;
  },

  refreshAccounts: async () => {
    const response = await apiClient.post('/api/accounts/refresh');
    return response.data;
  },

  // Utility
  getHealth: async () => {
    const response = await apiClient.get('/health');
    return response.data;
  },
};

export default apiClient;