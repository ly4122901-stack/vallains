import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import NavBar from '../components/NavBar';
import Loader from '../components/Loader';
import toast from 'react-hot-toast';
import {
  ArrowRight,
  Download,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  RefreshCw,
  Globe,
  Lock,
  Server,
  Database,
  Link,
  Terminal,
  Eye,
  ExternalLink,
  Copy,
  ChevronDown,
  ChevronUp,
  Clock,
} from 'lucide-react';

const ResultsPage = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('overview');
  const [expandedSections, setExpandedSections] = useState({});
  const [copyFeedback, setCopyFeedback] = useState(null);

  useEffect(() => {
    fetchScanResults();
  }, [id]);

  const fetchScanResults = async () => {
    setLoading(true);
    try {
      const data = await api.getScanById(id);
      setScan(data);
    } catch (error) {
      toast.error('فشل في تحميل نتائج الفحص');
      navigate('/dashboard');
    } finally {
      setLoading(false);
    }
  };

  const handleExport = () => {
    const reportData = JSON.stringify(scan, null, 2);
    const blob = new Blob([reportData], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `vallains-security-scan-${id}-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast.success('تم تحميل التقرير بنجاح ✓');
  };

  const handleCopy = (text, section) => {
    navigator.clipboard.writeText(text);
    setCopyFeedback(section);
    setTimeout(() => setCopyFeedback(null), 2000);
  };

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  const formatDate = (dateString) => {
    return new Date(dateString).toLocaleDateString('ar-SA', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  const getGradeColor = (grade) => {
    switch (grade) {
      case 'A': return '#10b981';
      case 'B': return '#22c55e';
      case 'C': return '#eab308';
      case 'D': return '#f97316';
      case 'F': return '#ef4444';
      default: return '#6b7280';
    }
  };

  const getSeverityIcon = (severity) => {
    switch (severity) {
      case 'critical': return <XCircle size={18} className="severity-critical" />;
      case 'high': return <AlertTriangle size={18} className="severity-high" />;
      case 'medium': return <AlertTriangle size={18} className="severity-medium" />;
      case 'low': return <Info size={18} className="severity-low" />;
      default: return <CheckCircle size={18} className="severity-info" />;
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'var(--danger)';
      case 'high': return 'var(--warning)';
      case 'medium': return 'var(--accent)';
      case 'low': return 'var(--info)';
      default: return 'var(--text-secondary)';
    }
  };

  if (loading) {
    return (
      <div className="results-page">
        <NavBar />
        <div className="results-loading">
          <Loader />
          <p>جاري تحميل نتائج الفحص...</p>
        </div>
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="results-page">
        <NavBar />
        <div className="results-error">
          <AlertTriangle size={64} />
          <h2>لم يتم العثور على الفحص</h2>
          <button className="btn-primary" onClick={() => navigate('/dashboard')}>
            <ArrowRight size={18} />
            <span>العودة للوحة التحكم</span>
          </button>
        </div>
      </div>
    );
  }

  const summary = scan.summary || { critical: 0, high: 0, medium: 0, info: 0, grade: 'N/A' };
  const results = scan.results || {};

  return (
    <div className="results-page">
      <NavBar />

      <div className="results-content">
        {/* Header */}
        <header className="results-header">
          <div className="header-info">
            <button className="btn-back" onClick={() => navigate('/dashboard')}>
              <ArrowRight size={20} />
            </button>
            <div className="header-title">
              <h1>تقرير الفحص الأمني</h1>
              <div className="scan-meta">
                <span className="meta-item">
                  <Globe size={16} />
                  {scan.target}
                </span>
                <span className="meta-item">
                  <Clock size={16} />
                  {scan.startedAt ? formatDate(scan.startedAt) : 'غير محدد'}
                </span>
              </div>
            </div>
          </div>

          <div className="header-actions">
            <button className="btn-icon" onClick={fetchScanResults} title="تحديث">
              <RefreshCw size={20} />
            </button>
            <button className="btn-primary" onClick={handleExport}>
              <Download size={18} />
              <span>تحميل التقرير</span>
            </button>
          </div>
        </header>

        {/* Security Grade */}
        <div className="grade-section" style={{ borderColor: getGradeColor(summary.grade) }}>
          <div className="grade-badge" style={{ backgroundColor: getGradeColor(summary.grade) }}>
            {summary.grade}
          </div>
          <div className="grade-info">
            <h2>التقييم الأمني العام</h2>
            <p>{getGradeDescription(summary.grade)}</p>
          </div>
          <div className="grade-stats">
            <div className="grade-stat critical">
              <XCircle size={20} />
              <span>{summary.critical}</span>
              <label>حرج</label>
            </div>
            <div className="grade-stat high">
              <AlertTriangle size={20} />
              <span>{summary.high}</span>
              <label>عالي</label>
            </div>
            <div className="grade-stat medium">
              <AlertTriangle size={20} />
              <span>{summary.medium}</span>
              <label>متوسط</label>
            </div>
            <div className="grade-stat info">
              <Info size={20} />
              <span>{summary.info}</span>
              <label>معلومات</label>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="results-tabs">
          <button
            className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveTab('overview')}
          >
            <Eye size={18} />
            <span>نظرة عامة</span>
          </button>
          <button
            className={`tab-btn ${activeTab === 'vulnerabilities' ? 'active' : ''}`}
            onClick={() => setActiveTab('vulnerabilities')}
          >
            <AlertTriangle size={18} />
            <span>الثغرات</span>
            {results.vulnerabilities?.length > 0 && (
              <span className="tab-badge">{results.vulnerabilities.length}</span>
            )}
          </button>
          <button
            className={`tab-btn ${activeTab === 'network' ? 'active' : ''}`}
            onClick={() => setActiveTab('network')}
          >
            <Globe size={18} />
            <span>الشبكة</span>
          </button>
          <button
            className={`tab-btn ${activeTab === 'security' ? 'active' : ''}`}
            onClick={() => setActiveTab('security')}
          >
            <Shield size={18} />
            <span>الأمان</span>
          </button>
        </div>

        {/* Tab Content */}
        <div className="tab-content">
          {/* Overview Tab */}
          {activeTab === 'overview' && (
            <div className="overview-section">
              {/* DNS Results */}
              {results.dns && (
                <div className="result-card">
                  <div className="card-header" onClick={() => toggleSection('dns')}>
                    <div className="card-title">
                      <Globe size={20} />
                      <h3>DNS</h3>
                    </div>
                    <button className="btn-expand">
                      {expandedSections.dns ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                    </button>
                  </div>
                  {expandedSections.dns && (
                    <div className="card-body">
                      <pre className="code-block">
                        {JSON.stringify(results.dns, null, 2)}
                      </pre>
                    </div>
                  )}
                </div>
              )}

              {/* SSL Results */}
              {results.ssl && (
                <div className="result-card">
                  <div className="card-header" onClick={() => toggleSection('ssl')}>
                    <div className="card-title">
                      <Lock size={20} />
                      <h3>شهادة SSL/TLS</h3>
                      {results.ssl.valid ? (
                        <span className="status-badge success">صالح ✓</span>
                      ) : (
                        <span className="status-badge danger">غير صالح ✗</span>
                      )}
                    </div>
                    <button className="btn-expand">
                      {expandedSections.ssl ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                    </button>
                  </div>
                  {expandedSections.ssl && (
                    <div className="card-body">
                      <div className="info-grid">
                        <div className="info-item">
                          <label>الحالة</label>
                          <span className={results.ssl.valid ? 'text-success' : 'text-danger'}>
                            {results.ssl.valid ? 'صالح' : 'غير صالح'}
                          </span>
                        </div>
                        {results.ssl.issuer && (
                          <div className="info-item">
                            <label>المُصدر</label>
                            <span>{results.ssl.issuer}</span>
                          </div>
                        )}
                        {results.ssl.expiry && (
                          <div className="info-item">
                            <label>تاريخ الانتهاء</label>
                            <span>{results.ssl.expiry}</span>
                          </div>
                        )}
                        {results.ssl.protocol && (
                          <div className="info-item">
                            <label>البروتوكول</label>
                            <span>{results.ssl.protocol}</span>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* Port Scan Results */}
              {results.ports && (
                <div className="result-card">
                  <div className="card-header" onClick={() => toggleSection('ports')}>
                    <div className="card-title">
                      <Server size={20} />
                      <h3>فحص المنافذ</h3>
                    </div>
                    <span className="port-count">{results.ports.open?.length || 0} مفتوح</span>
                    <button className="btn-expand">
                      {expandedSections.ports ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                    </button>
                  </div>
                  {expandedSections.ports && (
                    <div className="card-body">
                      {results.ports.open && results.ports.open.length > 0 ? (
                        <div className="ports-list">
                          {results.ports.open.map((port, idx) => (
                            <div key={idx} className="port-item">
                              <span className="port-number">{port.port}</span>
                              <span className="port-service">{port.service || 'غير معروف'}</span>
                              <span className={`port-status ${port.risky ? 'risky' : 'safe'}`}>
                                {port.risky ? '⚠️ خطير' : '✓ آمن'}
                              </span>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="no-data">لم يتم العثور على منافذ مفتوحة</p>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Security Headers */}
              {results.securityHeaders && (
                <div className="result-card">
                  <div className="card-header" onClick={() => toggleSection('headers')}>
                    <div className="card-title">
                      <Shield size={20} />
                      <h3>ترويسات الأمان</h3>
                    </div>
                    <span className="header-count">
                      {results.securityHeaders.present?.length || 0}/{results.securityHeaders.missing?.length + (results.securityHeaders.present?.length || 0)}
                    </span>
                    <button className="btn-expand">
                      {expandedSections.headers ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                    </button>
                  </div>
                  {expandedSections.headers && (
                    <div className="card-body">
                      {results.securityHeaders.present?.length > 0 && (
                        <div className="headers-section">
                          <h4>✓ موجودة</h4>
                          {results.securityHeaders.present.map((h, idx) => (
                            <div key={idx} className="header-item present">
                              <code>{h.name}</code>
                              <span>{h.value}</span>
                            </div>
                          ))}
                        </div>
                      )}
                      {results.securityHeaders.missing?.length > 0 && (
                        <div className="headers-section">
                          <h4>✗ مفقودة</h4>
                          {results.securityHeaders.missing.map((h, idx) => (
                            <div key={idx} className="header-item missing">
                              <code>{h}</code>
                              <span>غير موجودة</span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )}

              {/* Subdomains */}
              {results.subdomains && (
                <div className="result-card">
                  <div className="card-header" onClick={() => toggleSection('subdomains')}>
                    <div className="card-title">
                      <Link size={20} />
                      <h3>النطاقات الفرعية</h3>
                    </div>
                    <span className="subdomain-count">{results.subdomains.length || 0}</span>
                    <button className="btn-expand">
                      {expandedSections.subdomains ? <ChevronUp size={20} /> : <ChevronDown size={20} />}
                    </button>
                  </div>
                  {expandedSections.subdomains && (
                    <div className="card-body">
                      {results.subdomains.length > 0 ? (
                        <div className="subdomains-list">
                          {results.subdomains.map((sub, idx) => (
                            <div key={idx} className="subdomain-item">
                              <span>{sub}</span>
                              <button
                                className="btn-copy"
                                onClick={(e) => { e.stopPropagation(); handleCopy(sub, `sub-${idx}`); }}
                              >
                                {copyFeedback === `sub-${idx}` ? '✓' : <Copy size={14} />}
                              </button>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="no-data">لم يتم العثور على نطاقات فرعية</p>
                      )}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Vulnerabilities Tab */}
          {activeTab === 'vulnerabilities' && (
            <div className="vulnerabilities-section">
              {results.vulnerabilities && results.vulnerabilities.length > 0 ? (
                results.vulnerabilities.map((vuln, idx) => (
                  <div key={idx} className="vuln-card" style={{ borderRightColor: getSeverityColor(vuln.severity) }}>
                    <div className="vuln-header">
                      <div className="vuln-title">
                        {getSeverityIcon(vuln.severity)}
                        <h3>{vuln.name || vuln.type || 'ثغرة'}</h3>
                        <span className={`severity-badge ${vuln.severity}`}>{vuln.severity}</span>
                      </div>
                    </div>
                    <div className="vuln-body">
                      <div className="vuln-info">
                        <div className="info-row">
                          <label>الوصف:</label>
                          <span>{vuln.description || 'تم اكتشاف ثغرة محتملة.'}</span>
                        </div>
                        {vuln.payload && (
                          <div className="info-row">
                            <label>الحمولة:</label>
                            <code className="payload-code">{vuln.payload}</code>
                            <button className="btn-copy-small" onClick={() => handleCopy(vuln.payload, `payload-${idx}`)}>
                              {copyFeedback === `payload-${idx}` ? '✓' : <Copy size={12} />}
                            </button>
                          </div>
                        )}
                        {vuln.param && (
                          <div className="info-row">
                            <label>المعامل:</label>
                            <code>{vuln.param}</code>
                          </div>
                        )}
                        {vuln.confidence && (
                          <div className="info-row">
                            <label>الثقة:</label>
                            <span className={`confidence-${vuln.confidence}`}>{vuln.confidence}</span>
                          </div>
                        )}
                      </div>
                      {vuln.evidence && (
                        <div className="vuln-evidence">
                          <label>الدليل:</label>
                          <pre className="evidence-code">{vuln.evidence}</pre>
                        </div>
                      )}
                      <div className="vuln-recommendation">
                        <h4>💡 التوصية:</h4>
                        <p>{getRecommendation(vuln)}</p>
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="no-vulns">
                  <CheckCircle size={64} className="text-success" />
                  <h3>لم يتم اكتشاف ثغرات!</h3>
                  <p>الفحص آمن - لم يتم العثور على ثغرات أمنية معروفة.</p>
                </div>
              )}
            </div>
          )}

          {/* Network Tab */}
          {activeTab === 'network' && (
            <div className="network-section">
              {results.geoip && (
                <div className="result-card">
                  <div className="card-header">
                    <div className="card-title">
                      <Globe size={20} />
                      <h3>المعلومات الجغرافية</h3>
                    </div>
                  </div>
                  <div className="card-body">
                    <div className="info-grid">
                      {results.geoip.country && (
                        <div className="info-item">
                          <label>الدولة</label>
                          <span>{results.geoip.country}</span>
                        </div>
                      )}
                      {results.geoip.city && (
                        <div className="info-item">
                          <label>المدينة</label>
                          <span>{results.geoip.city}</span>
                        </div>
                      )}
                      {results.geoip.isp && (
                        <div className="info-item">
                          <label>مزود الخدمة</label>
                          <span>{results.geoip.isp}</span>
                        </div>
                      )}
                      {results.geoip.ip && (
                        <div className="info-item">
                          <label>عنوان IP</label>
                          <code>{results.geoip.ip}</code>
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {results.blacklist && (
                <div className="result-card">
                  <div className="card-header">
                    <div className="card-title">
                      <AlertTriangle size={20} />
                      <h3>قوائم الحظر</h3>
                      {results.blacklist.listed ? (
                        <span className="status-badge danger">مدرج ✗</span>
                      ) : (
                        <span className="status-badge success">نظيف ✓</span>
                      )}
                    </div>
                  </div>
                  <div className="card-body">
                    {results.blacklist.listed ? (
                      <div className="blacklist-info">
                        <p className="text-danger">تم اكتشاف هذا العنوان في {results.blacklist.count || 0} قائمة حظر.</p>
                        {results.blacklist.lists && (
                          <ul className="blacklist-list">
                            {results.blacklist.lists.map((list, idx) => (
                              <li key={idx}>{list}</li>
                            ))}
                          </ul>
                        )}
                      </div>
                    ) : (
                      <p className="text-success">✓ لم يتم العثور على هذا العنوان في أي قائمة حظر.</p>
                    )}
                  </div>
                </div>
              )}

              {results.redirects && (
                <div className="result-card">
                  <div className="card-header">
                    <div className="card-title">
                      <Terminal size={20} />
                      <h3>سلسلة إعادة التوجيه</h3>
                    </div>
                  </div>
                  <div className="card-body">
                    {results.redirects.chain && results.redirects.chain.length > 0 ? (
                      <div className="redirect-chain">
                        {results.redirects.chain.map((r, idx) => (
                          <div key={idx} className="redirect-step">
                            <span className="step-num">{idx + 1}</span>
                            <code>{r.url}</code>
                            <span className="step-status">{r.status}</span>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="no-data">لا توجد إعادة توجيه</p>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Security Tab */}
          {activeTab === 'security' && (
            <div className="security-section">
              {results.ssl && (
                <div className="result-card">
                  <div className="card-header">
                    <div className="card-title">
                      <Lock size={20} />
                      <h3>SSL/TLS</h3>
                    </div>
                  </div>
                  <div className="card-body">
                    <div className="ssl-details">
                      <div className="ssl-row">
                        <span>إصدار TLS</span>
                        <span className={results.ssl.protocol >= 1.2 ? 'text-success' : 'text-danger'}>
                          {results.ssl.protocol || 'غير محدد'}
                          {results.ssl.protocol >= 1.2 ? ' ✓ آمن' : ' ⚠️ قديم'}
                        </span>
                      </div>
                      <div className="ssl-row">
                        <span>تشفير</span>
                        <span>{results.ssl.cipher || 'غير محدد'}</span>
                      </div>
                      <div className="ssl-row">
                        <span>صالح</span>
                        <span className={results.ssl.valid ? 'text-success' : 'text-danger'}>
                          {results.ssl.valid ? '✓' : '✗'}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Scan Engine Info */}
              <div className="result-card">
                <div className="card-header">
                  <div className="card-title">
                    <Database size={20} />
                    <h3>محرك الفحص</h3>
                  </div>
                </div>
                <div className="card-body">
                  <div className="scan-engine-info">
                    <div className="info-row">
                      <label>محرك الفحص:</label>
                      <span>Vallains Security Scanner v1.0</span>
                    </div>
                    <div className="info-row">
                      <label>الفحوصات:</label>
                      <span>
                        SQLi, XSS, Open Redirect, SSRF, Directory Traversal, CMDi, CORS, XXE
                      </span>
                    </div>
                    <div className="info-row">
                      <label>الحالة:</label>
                      <span className="text-success">{scan.status}</span>
                    </div>
                    {scan.completedAt && (
                      <div className="info-row">
                        <label>أُنجز في:</label>
                        <span>{scan.completedAt}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      <style>{`
        .results-page { min-height: 100vh; background: var(--bg-primary); }
        .results-content { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        
        .results-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem; }
        .header-info { display: flex; align-items: center; gap: 1rem; }
        .btn-back { background: var(--bg-secondary); border: 1px solid var(--gold); color: var(--gold); width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.3s; }
        .btn-back:hover { background: var(--gold); color: var(--bg-primary); }
        .header-title h1 { font-size: 1.5rem; color: var(--gold); margin: 0 0 0.5rem 0; }
        .scan-meta { display: flex; gap: 1.5rem; }
        .meta-item { display: flex; align-items: center; gap: 0.5rem; color: var(--text-secondary); font-size: 0.9rem; }
        .header-actions { display: flex; gap: 0.75rem; }
        .btn-icon { background: var(--bg-secondary); border: 1px solid var(--border); color: var(--text-primary); width: 40px; height: 40px; border-radius: 8px; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.3s; }
        .btn-icon:hover { border-color: var(--gold); color: var(--gold); }
        .btn-primary { background: var(--gold); color: var(--bg-primary); border: none; padding: 0.75rem 1.5rem; border-radius: 8px; font-weight: 600; display: flex; align-items: center; gap: 0.5rem; cursor: pointer; transition: all 0.3s; }
        .btn-primary:hover { background: #b8941f; }
        
        .grade-section { display: flex; align-items: center; gap: 2rem; padding: 1.5rem; background: var(--bg-secondary); border-radius: 12px; border: 2px solid; margin-bottom: 2rem; }
        .grade-badge { width: 80px; height: 80px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2.5rem; font-weight: bold; color: white; }
        .grade-info h2 { color: var(--text-primary); margin: 0 0 0.5rem 0; }
        .grade-info p { color: var(--text-secondary); margin: 0; }
        .grade-stats { display: flex; gap: 1rem; margin-right: auto; }
        .grade-stat { display: flex; flex-direction: column; align-items: center; padding: 0.75rem 1rem; background: var(--bg-primary); border-radius: 8px; min-width: 70px; }
        .grade-stat span { font-size: 1.25rem; font-weight: bold; }
        .grade-stat label { font-size: 0.75rem; color: var(--text-secondary); }
        .grade-stat.critical { color: #ef4444; }
        .grade-stat.high { color: #f97316; }
        .grade-stat.medium { color: #eab308; }
        .grade-stat.info { color: var(--text-secondary); }
        
        .results-tabs { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); }
        .tab-btn { background: none; border: none; padding: 1rem 1.5rem; color: var(--text-secondary); display: flex; align-items: center; gap: 0.5rem; cursor: pointer; border-bottom: 2px solid transparent; transition: all 0.3s; }
        .tab-btn:hover { color: var(--text-primary); }
        .tab-btn.active { color: var(--gold); border-bottom-color: var(--gold); }
        .tab-badge { background: var(--danger); color: white; padding: 0.1rem 0.5rem; border-radius: 10px; font-size: 0.75rem; }
        
        .result-card { background: var(--bg-secondary); border-radius: 12px; margin-bottom: 1rem; overflow: hidden; }
        .card-header { display: flex; align-items: center; padding: 1rem 1.5rem; cursor: pointer; transition: background 0.3s; }
        .card-header:hover { background: var(--bg-tertiary); }
        .card-title { display: flex; align-items: center; gap: 0.75rem; flex: 1; }
        .card-title h3 { margin: 0; font-size: 1rem; color: var(--text-primary); }
        .btn-expand { background: none; border: none; color: var(--text-secondary); cursor: pointer; }
        .card-body { padding: 0 1.5rem 1.5rem; }
        
        .code-block { background: var(--bg-primary); padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; color: var(--text-secondary); }
        
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .info-item { display: flex; flex-direction: column; gap: 0.25rem; }
        .info-item label { font-size: 0.75rem; color: var(--text-secondary); text-transform: uppercase; }
        .info-item span, .info-item code { color: var(--text-primary); }
        .info-row { display: flex; gap: 0.75rem; margin-bottom: 0.5rem; }
        .info-row label { color: var(--text-secondary); min-width: 80px; }
        
        .status-badge { padding: 0.25rem 0.75rem; border-radius: 20px; font-size: 0.8rem; font-weight: 600; }
        .status-badge.success { background: rgba(16, 185, 129, 0.2); color: #10b981; }
        .status-badge.danger { background: rgba(239, 68, 68, 0.2); color: #ef4444; }
        
        .ports-list { display: flex; flex-direction: column; gap: 0.5rem; }
        .port-item { display: flex; align-items: center; gap: 1rem; padding: 0.75rem; background: var(--bg-primary); border-radius: 8px; }
        .port-number { font-weight: bold; color: var(--gold); min-width: 60px; }
        .port-service { flex: 1; color: var(--text-secondary); }
        .port-status { font-size: 0.85rem; }
        .port-status.risky { color: var(--danger); }
        .port-status.safe { color: var(--success); }
        
        .headers-section { margin-bottom: 1rem; }
        .headers-section h4 { margin: 0 0 0.5rem 0; font-size: 0.9rem; }
        .header-item { display: flex; justify-content: space-between; align-items: center; padding: 0.5rem 0.75rem; border-radius: 6px; margin-bottom: 0.5rem; }
        .header-item.present { background: rgba(16, 185, 129, 0.1); }
        .header-item.missing { background: rgba(239, 68, 68, 0.1); }
        .header-item code { color: var(--gold); font-size: 0.85rem; }
        .header-item span { font-size: 0.85rem; color: var(--text-secondary); }
        
        .subdomains-list { display: flex; flex-direction: column; gap: 0.5rem; }
        .subdomain-item { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem; background: var(--bg-primary); border-radius: 8px; }
        .subdomain-item span { font-family: monospace; color: var(--text-primary); }
        .btn-copy { background: none; border: none; color: var(--text-secondary); cursor: pointer; padding: 0.25rem; }
        .btn-copy:hover { color: var(--gold); }
        
        .vuln-card { background: var(--bg-secondary); border-radius: 12px; margin-bottom: 1rem; border-right: 4px solid; overflow: hidden; }
        .vuln-header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); }
        .vuln-title { display: flex; align-items: center; gap: 0.75rem; }
        .vuln-title h3 { margin: 0; font-size: 1rem; color: var(--text-primary); }
        .severity-badge { padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
        .severity-badge.critical { background: #ef4444; color: white; }
        .severity-badge.high { background: #f97316; color: white; }
        .severity-badge.medium { background: #eab308; color: black; }
        .severity-badge.low { background: #3b82f6; color: white; }
        .vuln-body { padding: 1.5rem; }
        .vuln-info { margin-bottom: 1rem; }
        .payload-code { background: var(--bg-primary); padding: 0.5rem; border-radius: 4px; font-family: monospace; }
        .btn-copy-small { background: none; border: none; cursor: pointer; color: var(--text-secondary); padding: 0.25rem; }
        .vuln-evidence { margin: 1rem 0; }
        .vuln-evidence label { display: block; margin-bottom: 0.5rem; color: var(--text-secondary); }
        .evidence-code { background: var(--bg-primary); padding: 1rem; border-radius: 8px; overflow-x: auto; font-size: 0.8rem; color: var(--danger); }
        .vuln-recommendation { background: rgba(16, 185, 129, 0.1); padding: 1rem; border-radius: 8px; }
        .vuln-recommendation h4 { margin: 0 0 0.5rem 0; color: var(--success); }
        .vuln-recommendation p { margin: 0; color: var(--text-primary); }
        
        .no-vulns { text-align: center; padding: 3rem; }
        .no-vulns h3 { color: var(--success); margin: 1rem 0 0.5rem 0; }
        .no-vulns p { color: var(--text-secondary); }
        
        .text-success { color: var(--success); }
        .text-danger { color: var(--danger); }
        .no-data { color: var(--text-secondary); font-style: italic; }
        
        .redirect-chain { display: flex; flex-direction: column; gap: 0.5rem; }
        .redirect-step { display: flex; align-items: center; gap: 1rem; padding: 0.75rem; background: var(--bg-primary); border-radius: 8px; }
        .step-num { width: 24px; height: 24px; background: var(--gold); color: var(--bg-primary); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 0.75rem; font-weight: bold; }
        .step-status { color: var(--text-secondary); font-size: 0.85rem; }
        
        .ssl-details { display: flex; flex-direction: column; gap: 0.75rem; }
        .ssl-row { display: flex; justify-content: space-between; padding: 0.75rem; background: var(--bg-primary); border-radius: 8px; }
        
        .severity-critical { color: #ef4444; }
        .severity-high { color: #f97316; }
        .severity-medium { color: #eab308; }
        .severity-low { color: #3b82f6; }
        .severity-info { color: var(--text-secondary); }
      `}</style>
    </div>
  );
};

function getGradeDescription(grade) {
  switch (grade) {
    case 'A': return 'ممتاز! الموقع آمن بشكل كبير.';
    case 'B': return 'جيد. هناك بعض التحسينات المطلوبة.';
    case 'C': return 'مقبول. يُنصح بإصلاح بعض المشاكل.';
    case 'D': return 'ضعيف. هناك مشاكل أمنية خطيرة.';
    case 'F': return 'فاشل! ثغرات حرجة تحتاج اهتمام فوري.';
    default: return 'غير محدد';
  }
}

function getRecommendation(vuln) {
  const recommendations = {
    'sql-injection': 'استخدم استعلامات معدة مسبقاً (Prepared Statements) أو ORM. фильтруйте и валидируйте جميع مدخلات المستخدم.',
    'xss': 'قم بتشفير جميع المخرجات وتطبيق Content Security Policy (CSP). استخدم libraries مثل DOMPurify.',
    'open-redirect': 'لا تثق في مدخلات المستخدم في عمليات إعادة التوجيه. استخدم قائمة بيضاء من النطاقات المسموحة.',
    'ssrf': 'قم بإنشاء قائمة بيضاء من العناوين المسموح الوصول إليها. استخدم DNS resolvers منفصلة.',
    'directory-traversal': 'استخدم path.normalize() وتجنب استخدام مدخلات المستخدم في مسارات الملفات.',
    'cmdi': 'تجنب استخدام exec() أو shell commands مع مدخلات المستخدم. استخدم البدائل الآمنة.',
    'cors-misconfig': 'لا تستخدم * في Access-Control-Allow-Origin. حدد النطاقات المسموحة صراحةً.',
    'xxe': 'تعطيل XML external entity processing في محلل XML.'
  };
  return recommendations[vuln.type] || 'يُنصح بمراجعة الكود والتطبيق مع مختص أمني.';
}

export default ResultsPage;