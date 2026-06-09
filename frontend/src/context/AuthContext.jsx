import React, { createContext, useContext, useState, useCallback } from 'react';
import { api } from '../api/client';

const AuthContext = createContext(null);

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [loading, setLoading] = useState(false);

  const BACKEND_URL = import.meta.env.VITE_API_URL || 'http://localhost:3000';

  const loginWithGoogle = useCallback(() => {
    window.location.href = `${BACKEND_URL}/auth/google`;
  }, [BACKEND_URL]);

  const loginWithGitHub = useCallback(() => {
    window.location.href = `${BACKEND_URL}/auth/github`;
  }, [BACKEND_URL]);

  const loginWithFacebook = useCallback(() => {
    window.location.href = `${BACKEND_URL}/auth/facebook`;
  }, [BACKEND_URL]);

  const loginLocal = useCallback(async (email, password) => {
    setLoading(true);
    try {
      const response = await api.login(email, password);
      const { token, user: userData } = response;
      localStorage.setItem('vallains_token', token);
      setUser(userData);
      setIsLoggedIn(true);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        message: error.response?.data?.message || error.message || 'Login failed',
      };
    } finally {
      setLoading(false);
    }
  }, []);

  const register = useCallback(async (name, email, password) => {
    setLoading(true);
    try {
      const response = await api.register(name, email, password);
      const { token, user: userData } = response;
      localStorage.setItem('vallains_token', token);
      setUser(userData);
      setIsLoggedIn(true);
      return { success: true };
    } catch (error) {
      return {
        success: false,
        message: error.response?.data?.message || error.message || 'Registration failed',
      };
    } finally {
      setLoading(false);
    }
  }, []);

  const logout = useCallback(() => {
    localStorage.removeItem('vallains_token');
    setUser(null);
    setIsLoggedIn(false);
    window.location.href = '/';
  }, []);

  const fetchSession = useCallback(async () => {
    const token = localStorage.getItem('vallains_token');
    if (!token) {
      setLoading(false);
      return;
    }

    setLoading(true);
    try {
      const userData = await api.getSession();
      setUser(userData);
      setIsLoggedIn(true);
    } catch (error) {
      localStorage.removeItem('vallains_token');
      setUser(null);
      setIsLoggedIn(false);
    } finally {
      setLoading(false);
    }
  }, []);

  const value = {
    user,
    setUser,
    isLoggedIn,
    loading,
    loginWithGoogle,
    loginWithGitHub,
    loginWithFacebook,
    loginLocal,
    register,
    logout,
    fetchSession,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export default AuthContext;