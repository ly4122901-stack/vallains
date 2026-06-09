# 🔒 Vallains Security Scanner

<div align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-D4AF37?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Node-18+-339933?style=for-the-badge" alt="Node">
  <img src="https://img.shields.io/badge/License-MIT-D4AF37?style=for-the-badge" alt="License">
</div>

> 🚀 ماسح أمني شامل للمواقع والتطبيقات - يعرض النتائج مباشرة في الموقع

## ✨ المميزات

### 🔍 فحوصات أمنية شاملة
- **SQL Injection (SQLi)** - كشف ثغرات حقن SQL
- **Cross-Site Scripting (XSS)** - كشف ثغرات XSS
- **Open Redirect** - كشف ثغرات إعادة التوجيه المفتوحة
- **SSRF** - كشف ثغرات Server-Side Request Forgery
- **Directory Traversal** - كشف ثغرات التنقل في الملفات
- **Command Injection (CMDi)** - كشف ثغرات حقن الأوامر
- **CORS Misconfiguration** - كشف إعدادات CORS الخاطئة
- **XXE** - كشف ثغرات XML External Entity

### 🛡️ فحوصات إضافية
- فحص DNS
- فحص شهادة SSL/TLS
- فحص المنافذ المفتوحة
- البحث عن النطاقات الفرعية
- فحص قوائم الحظر (Blacklist)
- فحص الترويسات الأمنية
- معلومات جغرافية (GeoIP)

### 🔐 تسجيل الدخول OAuth
- تسجيل الدخول بـ Google
- تسجيل الدخول بـ GitHub
- اختيار حساب Google متعدد

### 🛡️ حماية DDoS
- Rate limiting لكل IP
- حماية من abuse الفحص
- Timeout للمconnections البطيئة

## 🚀 البدء السريع

### المتطلبات
- Node.js 18+
- MongoDB (أو MongoDB Atlas)
- OAuth credentials من Google, GitHub, Facebook

### التثبيت

```bash
# استنساخ المشروع
git clone https://github.com/YOUR_USERNAME/vallains.git
cd vallains

# تثبيت backend
cd backend
npm install
cp .env.example .env  # عدّل الإعدادات
npm start

# تثبيت frontend (في terminal جديد)
cd frontend
npm install
npm run dev
```

### إعداد المتغيرات البيئية

```env
# Backend (.env)
NODE_ENV=production
PORT=3000
MONGODB_URI=mongodb://localhost:27017/vallains
SESSION_SECRET=your-super-secret-key-here
FRONTEND_URL=http://localhost:5173

# OAuth - Google
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# OAuth - GitHub
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# OAuth - Facebook
FACEBOOK_CLIENT_ID=your-facebook-client-id
FACEBOOK_CLIENT_SECRET=your-facebook-client-secret
```

### إعداد OAuth

#### Google OAuth
1. اذهب إلى [Google Cloud Console](https://console.cloud.google.com/)
2. أنشئ مشروع جديد
3. فعّل Google+ API
4. أنشئ OAuth 2.0 credentials
5. أضف `http://localhost:3000/auth/google/callback` كـ redirect URI

#### GitHub OAuth
1. اذهب إلى [GitHub Developer Settings](https://github.com/settings/developers)
2. أنشئ OAuth App جديد
3. Homepage URL: `http://localhost:5173`
4. Authorization callback URL: `http://localhost:3000/auth/github/callback`

#### Facebook OAuth
1. اذهب إلى [Facebook Developers](https://developers.facebook.com/)
2. أنشئ App جديد
3. أضف Facebook Login product
4. أضف Valid OAuth Redirect URI: `http://localhost:3000/auth/facebook/callback`

## 📁 هيكل المشروع

```
vallains/
├── backend/
│   ├── config/
│   │   ├── passport.js      # إعدادات Passport OAuth
│   │   └── database.js     # إعدادات MongoDB
│   ├── middleware/
│   │   ├── auth.js          # Middleware المصادقة
│   │   └── ddos-protection.js  # حماية DDoS
│   ├── routes/
│   │   ├── auth.js          # مسارات OAuth
│   │   └── api.js           # مسارات API
│   ├── services/
│   │   ├── scan-engine.js   # محرك الفحص الرئيسي
│   │   ├── scanners/        # فاحصات الثغرات
│   │   │   ├── sql-injection.js
│   │   │   ├── xss.js
│   │   │   ├── open-redirect.js
│   │   │   ├── ssrf.js
│   │   │   ├── directory-traversal.js
│   │   │   ├── cmdi.js
│   │   │   ├── cors-misconfig.js
│   │   │   └── xxe.js
│   │   └── ...
│   ├── models/
│   │   └── User.js          # موديل المستخدم
│   └── server.js            # السيرفر الرئيسي
├── frontend/
│   ├── src/
│   │   ├── api/
│   │   │   └── client.js    # عميل API
│   │   ├── components/
│   │   │   ├── NavBar.jsx
│   │   │   ├── ScanCard.jsx
│   │   │   └── ...
│   │   ├── context/
│   │   │   └── AuthContext.jsx
│   │   ├── pages/
│   │   │   ├── Dashboard.jsx
│   │   │   ├── LoginPage.jsx
│   │   │   └── ResultsPage.jsx
│   │   ├── App.jsx
│   │   └── main.jsx
│   └── vite.config.js
└── README.md
```

## 🌐 API Endpoints

### الفحوصات
- `POST /api/scan` - بدء فحص جديد
- `GET /api/scan/:id` - الحصول على نتائج الفحص
- `GET /api/scans` - الحصول على سجل الفحوصات

### أدوات إضافية
- `POST /api/dns/lookup` - فحص DNS
- `GET /api/geoip/:ip` - معلومات GeoIP
- `POST /api/ssl/check` - فحص شهادة SSL
- `POST /api/ports/scan` - فحص المنافذ
- `POST /api/subdomains` - البحث عن النطاقات الفرعية
- `POST /api/blacklist/check` - فحص القوائم السوداء

## 🛡️ حماية DDoS

النظام يتضمن:
- **Rate Limiting**: 100 طلب/دقيقة لكل IP
- **Scan Limiting**: 10 فحوصات/دقيقة لكل مستخدم
- **Request Size Limit**: 100KB maximum
- **Timeout**: 30 ثانية للمconnections البطيئة

## 📦 النشر

### GitHub Pages (Frontend)
1. اضغط على زر "Deploy to GitHub Pages" أو استخدم GitHub Actions
2. أضف المتغيرات البيئية في repository secrets

### Railway / Render (Backend)
1. اربط repository مع Railway أو Render
2. أضف المتغيرات البيئية
3. اضبط health check endpoint إلى `/api/health`

## 📝 ملاحظات

- ⚠️ **للاستخدام فقط على مواقعك الخاصة أو مع إذن صريح**
- 🔒 تأكد من استخدام HTTPS دائماً
- 📊 النتائج تُعرض مباشرة في الموقع (ليست لينكات خارجية)

## 📄 الرخصة

MIT License - انظر ملف [LICENSE](LICENSE) للتفاصيل.

---

<div align="center">
  <p>صُنع بـ ❤️ بواسطة Vallains Security Team</p>
</div>