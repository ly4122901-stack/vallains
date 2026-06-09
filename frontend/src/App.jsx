import React, { useEffect, useState } from 'react';
import { Routes, Route, useNavigate, useLocation } from 'react-router-dom';
import { Toaster } from 'react-hot-toast';
import { useAuth } from './context/AuthContext';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';
import ResultsPage from './pages/ResultsPage';
import Loader from './components/Loader';

// Protected Route wrapper component
const ProtectedRoute = ({ children }) => {
  const { isLoggedIn, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    if (!loading && !isLoggedIn) {
      navigate('/', { replace: true });
    }
  }, [isLoggedIn, loading, navigate]);

  if (loading) {
    return <Loader fullScreen={true} />;
  }

  if (!isLoggedIn) {
    return null;
  }

  return children;
};

function App() {
  const { fetchSession, loading } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();

  // Check for OAuth callback token in URL
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');
    
    if (token) {
      localStorage.setItem('vallains_token', token);
      // Clean URL without reload
      window.history.replaceState({}, document.title, location.pathname);
      navigate('/dashboard', { replace: true });
    }
  }, [location.pathname, navigate]);

  // Validate session on app mount
  useEffect(() => {
    const token = localStorage.getItem('vallains_token');
    if (token && !loading) {
      fetchSession();
    }
  }, []);

  return (
    <>
      <Toaster
        position="top-center"
        toastOptions={{
          duration: 4000,
          style: {
            background: '#1a1a1f',
            color: '#f5f5f7',
            border: '1px solid #D4AF37',
            borderRadius: '12px',
            fontFamily: 'Cairo, sans-serif',
            fontSize: '14px',
            boxShadow: '0 4px 20px rgba(212, 175, 55, 0.15)',
          },
          success: {
            iconTheme: {
              primary: '#D4AF37',
              secondary: '#1a1a1f',
            },
          },
          error: {
            iconTheme: {
              primary: '#ef4444',
              secondary: '#1a1a1f',
            },
          },
        }}
      />
      <Routes>
        <Route path="/" element={<LoginPage />} />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <Dashboard />
            </ProtectedRoute>
          }
        />
        <Route
          path="/results/:id"
          element={
            <ProtectedRoute>
              <ResultsPage />
            </ProtectedRoute>
          }
        />
      </Routes>
    </>
  );
}

export default App;