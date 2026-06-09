import React, { useState, useEffect } from 'react';
import { X, Shield, CheckCircle, AlertTriangle, Loader } from 'lucide-react';
import { api } from '../api/client';
import toast from 'react-hot-toast';

const ComprehensiveScanModal = ({ account, onClose, onComplete }) => {
  const [step, setStep] = useState('config');
  const [progress, setProgress] = useState(0);
  const [currentCheck, setCurrentCheck] = useState('');
  const [scanId, setScanId] = useState(null);
  const [isScanning, setIsScanning] = useState(false);

  const scanSteps = [
    { id: 'account', name: 'فحص إعدادات الحساب', progress: 10 },
    { id: 'privacy', name: 'فحص إعدادات الخصوصية', progress: 30 },
    { id: 'security', name: 'فحص الأمان', progress: 50 },
    { id: 'visibility', name: 'فحص الرؤية', progress: 70 },
    { id: 'content', name: 'فحص المحتوى', progress: 90 },
    { id: 'finalize', name: 'إنهاء الفحص', progress: 100 },
  ];

  const handleStartScan = async () => {
    setStep('scanning');
    setIsScanning(true);

    try {
      // Simulate progress through steps
      for (let i = 0; i < scanSteps.length; i++) {
        const scanStep = scanSteps[i];
        setCurrentCheck(scanStep.name);
        setProgress(scanStep.progress);

        // Simulate API call for each step
        if (i === 0) {
          // Create scan
          const response = await api.scan({
            accountId: account?.id,
            accountEmail: account?.email,
            provider: account?.provider || 'google',
            type: 'comprehensive',
          });
          setScanId(response.scanId || response.id);
        } else {
          // Wait for simulated processing
          await new Promise((resolve) => setTimeout(resolve, 800));
        }
      }

      setStep('complete');
      setIsScanning(false);

      // Small delay before redirecting
      setTimeout(() => {
        if (scanId) {
          onComplete(scanId);
        } else {
          // If no scan ID, generate a mock one for demo
          onComplete('scan-' + Date.now());
        }
      }, 1500);
    } catch (error) {
      setIsScanning(false);
      toast.error('حدث خطأ أثناء الفحص');
      setStep('error');
    }
  };

  const getStepIcon = (stepIndex) => {
    const currentStepIndex = scanSteps.findIndex((s) => s.name === currentCheck);
    if (stepIndex < currentStepIndex) {
      return <CheckCircle size={24} />;
    } else if (stepIndex === currentStepIndex) {
      return <Loader size={24} className="spin" />;
    }
    return null;
  };

  const getStepStatus = (stepIndex) => {
    const currentStepIndex = scanSteps.findIndex((s) => s.name === currentCheck);
    if (stepIndex < currentStepIndex) return 'completed';
    if (stepIndex === currentStepIndex) return 'active';
    return 'pending';
  };

  return (
    <div className="modal-overlay">
      <div className="modal-content scan-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <div className="modal-title">
            <Shield className="shield-icon" />
            <h2>فحص شامل للأمان</h2>
          </div>
          {step !== 'scanning' && (
            <button className="modal-close" onClick={onClose}>
              <X size={24} />
            </button>
          )}
        </div>

        <div className="modal-body">
          {step === 'config' && (
            <div className="scan-config">
              <div className="config-info">
                <h3>正准备 الفحص الشامل</h3>
                <p>
                  سيقوم هذا الفحص بفحص جميع إعدادات الأمان والخصوصية لحسابك:
                </p>
                <ul className="config-list">
                  <li>إعدادات الخصوصية</li>
                  <li>الأمان وكلمات المرور</li>
                  <li>الرؤية والوصول</li>
                  <li>المحتوى العام</li>
                </ul>
              </div>

              {account && (
                <div className="selected-account">
                  <span className="label">الحساب المحدد:</span>
                  <span className="value">{account.email}</span>
                </div>
              )}

              <button className="btn-primary btn-large" onClick={handleStartScan}>
                <Shield size={20} />
                <span>بدء الفحص</span>
              </button>
            </div>
          )}

          {step === 'scanning' && (
            <div className="scan-progress">
              <div className="progress-header">
                <div className="progress-icon">
                  <Shield className="pulsing" />
                </div>
                <h3>جاري الفحص...</h3>
                <p>{currentCheck}</p>
              </div>

              <div className="progress-bar-container">
                <div className="progress-bar">
                  <div
                    className="progress-fill"
                    style={{ width: `${progress}%` }}
                  ></div>
                </div>
                <span className="progress-percent">{progress}%</span>
              </div>

              <div className="scan-steps">
                {scanSteps.map((scanStep, index) => (
                  <div
                    key={scanStep.id}
                    className={`scan-step ${getStepStatus(index)}`}
                  >
                    <div className="step-indicator">
                      {getStepIcon(index)}
                    </div>
                    <span className="step-name">{scanStep.name}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {step === 'complete' && (
            <div className="scan-complete">
              <div className="complete-icon">
                <CheckCircle />
              </div>
              <h3>اكتمل الفحص!</h3>
              <p>جاري تحميل النتائج...</p>
            </div>
          )}

          {step === 'error' && (
            <div className="scan-error">
              <div className="error-icon">
                <AlertTriangle />
              </div>
              <h3>حدث خطأ</h3>
              <p>فشل في إكمال الفحص. يرجى المحاولة مرة أخرى.</p>
              <button className="btn-primary" onClick={() => setStep('config')}>
                <span>إعادة المحاولة</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default ComprehensiveScanModal;