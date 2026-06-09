import React from 'react';
import { Shield } from 'lucide-react';

const Loader = ({ fullScreen = false, size = 'medium', text = '' }) => {
  const sizeClass = `loader-${size}`;

  if (fullScreen) {
    return (
      <div className="loader-fullscreen">
        <div className={`loader ${sizeClass}`}>
          <div className="loader-shield">
            <Shield className="shield-icon" />
          </div>
          <div className="loader-ring"></div>
        </div>
        {text && <p className="loader-text">{text}</p>}
      </div>
    );
  }

  return (
    <div className={`loader-container ${sizeClass}`}>
      <div className="loader">
        <div className="loader-shield">
          <Shield className="shield-icon" />
        </div>
        <div className="loader-ring"></div>
      </div>
      {text && <p className="loader-text">{text}</p>}
    </div>
  );
};

export default Loader;