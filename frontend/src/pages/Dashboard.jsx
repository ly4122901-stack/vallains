import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { api } from '../api/client';
import NavBar from '../components/NavBar';
import Loader from '../components/Loader';
import ScanCard from '../components/ScanCard';
import GoogleAccountPicker from '../components/GoogleAccountPicker';
import ComprehensiveScanModal from '../components/ComprehensiveScanModal';
import toast from 'react-hot-toast';
import {
  Search,
  History,
  Settings,
  Plus,
  RefreshCw,
  AlertCircle,
  Shield,
  Activity,
} from 'lucide-react';

const Dashboard = () => {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState('scan');
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [accounts, setAccounts] = useState([]);
  const [showAccountPicker, setShowAccountPicker] = useState(false);
  const [showScanModal, setShowScanModal] = useState(false);
  const [selectedAccount, setSelectedAccount] = useState(null);

  useEffect(() => {
    fetchScanHistory();
    fetchAccounts();
  }, []);

  const fetchScanHistory = async () => {
    setLoading(true);
    try {
      const data = await api.getScanHistory();
      setScans(data.scans || []);
    } catch (error) {
      toast.error('فشل في تحميل سجل الفحوصات');
    } finally {
      setLoading(false);
    }
  };

  const fetchAccounts = async () => {
    try {
      const data = await api.getAccounts();
      setAccounts(data.accounts || []);
    } catch (error) {
      console.error('Failed to fetch accounts:', error);
    }
  };

  const handleStartScan = () => {
    if (accounts.length > 0) {
      setShowAccountPicker(true);
    } else {
      setShowScanModal(true);
    }
  };

  const handleAccountSelect = (account) => {
    setSelectedAccount(account);
    setShowAccountPicker(false);
    setShowScanModal(true);
  };

  const handleRefreshAccounts = async () => {
    try {
      await api.refreshAccounts();
      toast.success('تم تحديث الحسابات');
      fetchAccounts();
    } catch (error) {
      toast.error('فشل في تحديث الحسابات');
    }
  };

  const handleViewResults = (scanId) => {
    navigate(`/results/${scanId}`);
  };

  const handleDeleteScan = async (scanId) => {
    try {
      await api.deleteScan(scanId);
      toast.success('تم حذف الفحص');
      fetchScanHistory();
    } catch (error) {
      toast.error('فشل في حذف الفحص');
    }
  };

  return (
    <div className="dashboard-page">
      <NavBar />

      <div className="dashboard-content">
        <header className="dashboard-header">
          <div className="welcome-section">
            <h1>
              <span className="welcome-text">مرحباً،</span>
              <span className="user-name">{user?.name || 'مستخدم'}</span>
            </h1>
            <p className="welcome-subtitle">كيف يمكنني مساعدتك اليوم؟</p>
          </div>

          <div className="header-actions">
            <button className="btn-action" onClick={handleStartScan}>
              <Plus size={20} />
              <span>فحص جديد</span>
            </button>
          </div>
        </header>

        <div className="stats-grid">
          <div className="stat-card">
            <div className="stat-icon">
              <Shield size={24} />
            </div>
            <div className="stat-info">
              <span className="stat-value">{scans.length}</span>
              <span className="stat-label">إجمالي الفحوصات</span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon">
              <Activity size={24} />
            </div>
            <div className="stat-info">
              <span className="stat-value">
                {scans.filter((s) => s.status === 'completed').length}
              </span>
              <span className="stat-label">فحوصات مكتملة</span>
            </div>
          </div>

          <div className="stat-card">
            <div className="stat-icon warning">
              <AlertCircle size={24} />
            </div>
            <div className="stat-info">
              <span className="stat-value">
                {scans.filter((s) => s.issues?.length > 0).length}
              </span>
              <span className="stat-label">مشاكل مكتشفة</span>
            </div>
          </div>
        </div>

        <div className="tabs-container">
          <div className="tabs">
            <button
              className={`tab ${activeTab === 'scan' ? 'active' : ''}`}
              onClick={() => setActiveTab('scan')}
            >
              <Search size={18} />
              <span>بدء فحص</span>
            </button>
            <button
              className={`tab ${activeTab === 'history' ? 'active' : ''}`}
              onClick={() => setActiveTab('history')}
            >
              <History size={18} />
              <span>سجل الفحوصات</span>
            </button>
            <button
              className={`tab ${activeTab === 'accounts' ? 'active' : ''}`}
              onClick={() => setActiveTab('accounts')}
            >
              <Settings size={18} />
              <span>الحسابات</span>
            </button>
          </div>

          <div className="tab-content">
            {activeTab === 'scan' && (
              <div className="scan-section">
                <div className="scan-options">
                  <div className="scan-card" onClick={handleStartScan}>
                    <div className="scan-card-icon">
                      <Shield size={48} />
                    </div>
                    <h3>فحص شامل</h3>
                    <p>فحص كامل لجميع إعدادات الخصوصية والأمان</p>
                  </div>

                  <div className="scan-card disabled">
                    <div className="scan-card-icon">
                      <Search size={48} />
                    </div>
                    <h3>فحص مخصص</h3>
                    <p>اختر الفئات التي تريد فحصها</p>
                    <span className="coming-soon">قريباً</span>
                  </div>
                </div>
              </div>
            )}

            {activeTab === 'history' && (
              <div className="history-section">
                {loading ? (
                  <Loader />
                ) : scans.length > 0 ? (
                  <div className="scans-grid">
                    {scans.map((scan) => (
                      <ScanCard
                        key={scan.id}
                        scan={scan}
                        onView={() => handleViewResults(scan.id)}
                        onDelete={() => handleDeleteScan(scan.id)}
                      />
                    ))}
                  </div>
                ) : (
                  <div className="empty-state">
                    <Search size={64} />
                    <h3>لا توجد فحوصات سابقة</h3>
                    <p>ابدأ بفحص جديد لاستكشاف إعدادات أمان حساباتك</p>
                    <button className="btn-primary" onClick={handleStartScan}>
                      <Plus size={18} />
                      <span>بدء فحص جديد</span>
                    </button>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'accounts' && (
              <div className="accounts-section">
                <div className="section-header">
                  <h3>الحسابات المرتبطة</h3>
                  <button
                    className="btn-secondary"
                    onClick={handleRefreshAccounts}
                  >
                    <RefreshCw size={18} />
                    <span>تحديث</span>
                  </button>
                </div>

                {accounts.length > 0 ? (
                  <div className="accounts-list">
                    {accounts.map((account) => (
                      <div key={account.id} className="account-item">
                        <div className="account-avatar">
                          {account.provider === 'google' && (
                            <svg viewBox="0 0 24 24" width="24" height="24">
                              <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                              <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                              <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                              <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                            </svg>
                          )}
                          {account.provider === 'github' && (
                            <svg viewBox="0 0 24 24" width="24" height="24" fill="currentColor">
                              <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/>
                            </svg>
                          )}
                        </div>
                        <div className="account-info">
                          <span className="account-name">{account.name}</span>
                          <span className="account-email">{account.email}</span>
                        </div>
                        <span className={`account-status ${account.active ? 'active' : 'inactive'}`}>
                          {account.active ? 'نشط' : 'غير نشط'}
                        </span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="empty-state small">
                    <Settings size={48} />
                    <p>لا توجد حسابات مرتبطة</p>
                    <button
                      className="btn-link"
                      onClick={() => window.location.href = '/'}
                    >
                      ربط حساب جديد
                    </button>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>

      {showAccountPicker && (
        <GoogleAccountPicker
          accounts={accounts}
          onSelect={handleAccountSelect}
          onClose={() => setShowAccountPicker(false)}
        />
      )}

      {showScanModal && (
        <ComprehensiveScanModal
          account={selectedAccount}
          onClose={() => {
            setShowScanModal(false);
            setSelectedAccount(null);
          }}
          onComplete={(scanId) => {
            setShowScanModal(false);
            setSelectedAccount(null);
            handleViewResults(scanId);
          }}
        />
      )}
    </div>
  );
};

export default Dashboard;