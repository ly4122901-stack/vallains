import React from 'react';
import { X, Check, AlertCircle, RefreshCw } from 'lucide-react';

const GoogleAccountPicker = ({ accounts, onSelect, onClose }) => {
  const [loading, setLoading] = React.useState(false);

  const handleSelect = (account) => {
    setLoading(true);
    // Small delay for UX
    setTimeout(() => {
      onSelect(account);
    }, 300);
  };

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-content account-picker-modal" onClick={(e) => e.stopPropagation()}>
        <div className="modal-header">
          <h2>اختر حساب Google</h2>
          <button className="modal-close" onClick={onClose}>
            <X size={24} />
          </button>
        </div>

        <div className="modal-body">
          <p className="modal-description">
            اختر حساب Google الذي تريد فحصه
          </p>

          <div className="accounts-list">
            {accounts.map((account) => (
              <button
                key={account.id}
                className="account-option"
                onClick={() => handleSelect(account)}
                disabled={loading}
              >
                <div className="account-avatar-large">
                  {account.avatar ? (
                    <img src={account.avatar} alt={account.name} />
                  ) : (
                    <span>{account.name?.charAt(0)?.toUpperCase()}</span>
                  )}
                </div>
                <div className="account-details">
                  <span className="account-name">{account.name}</span>
                  <span className="account-email">{account.email}</span>
                </div>
                {account.active && (
                  <Check size={20} className="check-icon" />
                )}
              </button>
            ))}
          </div>

          {accounts.length === 0 && (
            <div className="empty-accounts">
              <AlertCircle size={48} />
              <p>لا توجد حسابات Google متصلة</p>
            </div>
          )}
        </div>

        <div className="modal-footer">
          <button className="btn-secondary" onClick={onClose}>
            <span>إلغاء</span>
          </button>
        </div>
      </div>
    </div>
  );
};

export default GoogleAccountPicker;