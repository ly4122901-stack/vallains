import React, { useState } from 'react';
import { ChevronDown, ChevronUp, CheckCircle, AlertTriangle, Info, Clock, ExternalLink } from 'lucide-react';

const ResultsViewer = ({ results, getStatusColor, getStatusIcon }) => {
  const [expandedItems, setExpandedItems] = useState({});

  const toggleExpand = (id) => {
    setExpandedItems((prev) => ({
      ...prev,
      [id]: !prev[id],
    }));
  };

  const getCategoryLabel = (category) => {
    const labels = {
      privacy: 'الخصوصية',
      security: 'الأمان',
      visibility: 'الرؤية',
      account: 'الحساب',
      content: 'المحتوى',
    };
    return labels[category] || category;
  };

  const getSeverityClass = (severity) => {
    switch (severity) {
      case 'critical':
        return 'severity-critical';
      case 'high':
        return 'severity-high';
      case 'medium':
        return 'severity-medium';
      case 'low':
        return 'severity-low';
      default:
        return '';
    }
  };

  if (!results || results.length === 0) {
    return (
      <div className="results-empty">
        <CheckCircle size={64} />
        <h3>لا توجد نتائج</h3>
        <p>لم يتم العثور على نتائج تطابق معايير البحث</p>
      </div>
    );
  }

  return (
    <div className="results-viewer">
      {results.map((result) => (
        <div
          key={result.id || result.checkId}
          className={`result-item ${getStatusColor(result.status)} ${getSeverityClass(result.severity)}`}
        >
          <div
            className="result-header"
            onClick={() => toggleExpand(result.id || result.checkId)}
          >
            <div className="result-status">
              {getStatusIcon(result.status)}
            </div>

            <div className="result-info">
              <h4 className="result-title">{result.title}</h4>
              <div className="result-meta">
                <span className="category-badge">
                  {getCategoryLabel(result.category)}
                </span>
                {result.severity && (
                  <span className={`severity-badge ${getSeverityClass(result.severity)}`}>
                    {result.severity}
                  </span>
                )}
              </div>
            </div>

            <div className="result-toggle">
              {expandedItems[result.id || result.checkId] ? (
                <ChevronUp size={20} />
              ) : (
                <ChevronDown size={20} />
              )}
            </div>
          </div>

          {expandedItems[result.id || result.checkId] && (
            <div className="result-content">
              <div className="result-description">
                <h5>الوصف</h5>
                <p>{result.description || result.message}</p>
              </div>

              {result.currentValue !== undefined && (
                <div className="result-current">
                  <h5>القيمة الحالية</h5>
                  <code>{result.currentValue}</code>
                </div>
              )}

              {result.recommendedValue !== undefined && (
                <div className="result-recommended">
                  <h5>القيمة الموصى بها</h5>
                  <code>{result.recommendedValue}</code>
                </div>
              )}

              {result.action && (
                <div className="result-action">
                  <h5>الإجراء المطلوب</h5>
                  <p>{result.action}</p>
                </div>
              )}

              {result.link && (
                <div className="result-link">
                  <a href={result.link} target="_blank" rel="noopener noreferrer">
                    <ExternalLink size={16} />
                    <span>مزيد من المعلومات</span>
                  </a>
                </div>
              )}

              {result.fixInstructions && (
                <div className="result-fix">
                  <h5>خطوات الإصلاح</h5>
                  <ol>
                    {result.fixInstructions.map((step, index) => (
                      <li key={index}>{step}</li>
                    ))}
                  </ol>
                </div>
              )}
            </div>
          )}
        </div>
      ))}
    </div>
  );
};

export default ResultsViewer;