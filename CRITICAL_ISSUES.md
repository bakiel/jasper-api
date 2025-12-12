# CRITICAL ISSUES - IMMEDIATE ACTION REQUIRED

**Date:** December 11, 2025
**System:** JASPER Portal (https://portal.jasperfinance.org)
**Status:** 🔴 NOT PRODUCTION READY

---

## 🚨 BLOCKER: Admin Login Endpoint Failing

**Severity:** CRITICAL (P0)
**Impact:** System completely unusable for authenticated users

### Problem
The admin login endpoint at `POST /api/v1/admin/auth/login` returns **400 Bad Request** for all login attempts.

### Root Cause
File: `/Users/mac/Downloads/jasper-financial-architecture/jasper-api/api/admin/auth/login.js`

**Lines 42-50:**
```javascript
// This code is incompatible with Vercel serverless functions
const chunks = [];
for await (const chunk of req) {
  chunks.push(chunk);
}
const rawBody = Buffer.concat(chunks).toString('utf8');

if (!rawBody || rawBody.trim() === '') {
  return res.status(400).json({ detail: 'Request body is required' });
}
```

**Why it fails:**
- Vercel automatically parses request bodies
- The stream is already consumed before your code runs
- Manual stream reading returns empty buffer
- Code incorrectly thinks no body was sent

### Fix (5 minutes)

Replace lines 42-64 with:

```javascript
try {
  const body = req.body;

  if (!body || Object.keys(body).length === 0) {
    return res.status(400).json({ detail: 'Request body is required' });
  }

  const email = body.email;
  const password = body.password;

  if (!email || !password) {
    return res.status(400).json({ detail: 'Email and password required' });
  }
```

### Test After Fix
```bash
curl -X POST https://api.jasperfinance.org/api/v1/admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@jasperfinance.org","password":"Admin123!"}'
```

**Expected result:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "expires_in": 28800,
  "user": {
    "id": 123456,
    "email": "admin@jasperfinance.org",
    "role": "admin"
  }
}
```

---

## 🚨 SECURITY: Missing Production Environment Variables

**Severity:** CRITICAL (P0)
**Impact:** Authentication and email features will fail

### Missing Variables

Add these to Vercel Environment Variables:

```bash
# Required for JWT token signing (CRITICAL)
SECRET_KEY=<generate-secure-64-char-random-string>

# Admin authentication (CRITICAL)
ADMIN_EMAIL=admin@jasperfinance.org
ADMIN_PASSWORD=<create-strong-password>

# Email functionality (CRITICAL)
SMTP_HOST=smtp.hostinger.com
SMTP_PORT=587
SMTP_USER=models@jasperfinance.org
SMTP_PASS=<your-hostinger-smtp-password>

# CRM integration (IMPORTANT)
CRM_API_URL=http://72.61.201.237:8001
WEBHOOK_SECRET=<generate-secure-random-string>
```

### How to Add (Vercel Dashboard)

1. Go to https://vercel.com/your-project/settings/environment-variables
2. Add each variable above
3. Select all environments (Production, Preview, Development)
4. Click "Save"
5. Redeploy the application

### Generate Secure Keys
```bash
# On macOS/Linux terminal:
openssl rand -hex 32  # For SECRET_KEY
openssl rand -hex 32  # For WEBHOOK_SECRET
```

---

## 🚨 SECURITY: Exposed SMTP Password in Repository

**Severity:** HIGH (P1)
**Impact:** Email account compromise

### Found In
File: `/Users/mac/Downloads/jasper-financial-architecture/jasper-api/.env.local`
Line 8: `SMTP_PASS=EG>pLVFz8*A`

### Immediate Actions Required

1. **Rotate Password NOW**
   - Log into Hostinger email panel
   - Change password for `models@jasperfinance.org`
   - Update Vercel environment variables
   - Update local `.env.local` file

2. **Check Repository History**
   ```bash
   cd /Users/mac/Downloads/jasper-financial-architecture/jasper-api
   git log --all --full-history -- .env.local
   ```

   If `.env.local` was ever committed:
   ```bash
   # Remove from history (use carefully)
   git filter-branch --force --index-filter \
     "git rm --cached --ignore-unmatch .env.local" \
     --prune-empty --tag-name-filter cat -- --all
   ```

3. **Verify `.gitignore`**
   ```bash
   grep .env.local .gitignore
   ```
   Should output: `.env.local` (already present ✓)

---

## ⚠️ IMPORTANT: No Database Persistence

**Severity:** HIGH (P1)
**Impact:** All data lost on server restart

### Current Implementation

**CRM Leads** (`/api/crm/leads.js` line 6):
```javascript
let leads = [];  // In-memory - LOST ON RESTART
```

**Rate Limiting** (`/api/contact.js` line 4):
```javascript
const rateLimitMap = new Map();  // In-memory - LOST ON RESTART
```

### Impact
- Every Vercel deployment = data loss
- Cold starts = data loss
- Multiple instances = inconsistent data

### Solution Options

#### Option 1: Vercel Postgres (Recommended)
```bash
# Install
npm install @vercel/postgres

# In Vercel dashboard:
# Storage → Create Database → Postgres
# Copy connection string to env vars
```

#### Option 2: Neon (Serverless Postgres)
```bash
# Free tier: 0.5 GB storage
# Good for MVP/testing
# https://neon.tech
```

#### Option 3: Supabase
```bash
# Includes auth, database, storage
# Free tier: 500 MB database
# https://supabase.com
```

### Database Schema Needed
```sql
CREATE TABLE leads (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) UNIQUE NOT NULL,
  name VARCHAR(255) NOT NULL,
  company VARCHAR(255) NOT NULL,
  phone VARCHAR(50),
  sector VARCHAR(100),
  funding_stage VARCHAR(100),
  funding_amount VARCHAR(100),
  message TEXT,
  source VARCHAR(50) DEFAULT 'website',
  status VARCHAR(50) DEFAULT 'new',
  notes JSONB,
  created_at TIMESTAMP DEFAULT NOW(),
  updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_leads_email ON leads(email);
CREATE INDEX idx_leads_status ON leads(status);
CREATE INDEX idx_leads_created_at ON leads(created_at DESC);
```

---

## ⚠️ IMPORTANT: CRM Endpoints Not Protected

**Severity:** HIGH (P1)
**Impact:** Lead data publicly accessible

### Vulnerable Endpoint
`GET /api/v1/crm/leads` - **NO AUTHENTICATION REQUIRED**

### Test (Anyone can do this)
```bash
curl https://api.jasperfinance.org/api/v1/crm/leads
```

Returns all leads with:
- Names
- Email addresses
- Companies
- Phone numbers
- Messages
- Financial information

### Fix Required

Add authentication middleware to `/api/crm/leads.js`:

```javascript
import { jwtVerify } from 'jose';

const SECRET_KEY = process.env.SECRET_KEY;

async function requireAuth(req) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return { error: 'Authentication required', status: 401 };
  }

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
    return { error: 'Invalid authorization header', status: 401 };
  }

  try {
    const token = parts[1];
    const secretKey = new TextEncoder().encode(SECRET_KEY);
    const { payload } = await jwtVerify(token, secretKey);

    if (payload.type !== 'admin') {
      return { error: 'Admin access required', status: 403 };
    }

    return { user: payload };
  } catch (error) {
    return { error: 'Invalid token', status: 401 };
  }
}

export default async function handler(req, res) {
  // Check authentication FIRST
  const auth = await requireAuth(req);
  if (auth.error) {
    return res.status(auth.status).json({ detail: auth.error });
  }

  // Continue with existing logic...
}
```

---

## Quick Fix Checklist

Use this checklist to fix all critical issues:

### Step 1: Fix Login Endpoint (15 minutes)
- [ ] Open `/api/admin/auth/login.js`
- [ ] Replace lines 42-64 with `req.body` approach (see above)
- [ ] Test locally with `npm run dev`
- [ ] Commit changes
- [ ] Deploy to Vercel

### Step 2: Add Environment Variables (10 minutes)
- [ ] Generate SECRET_KEY: `openssl rand -hex 32`
- [ ] Generate WEBHOOK_SECRET: `openssl rand -hex 32`
- [ ] Add all variables to Vercel dashboard
- [ ] Select all environments
- [ ] Save and redeploy

### Step 3: Rotate SMTP Password (5 minutes)
- [ ] Log into Hostinger
- [ ] Change password for `models@jasperfinance.org`
- [ ] Update password in Vercel env vars
- [ ] Update local `.env.local`
- [ ] Test email sending

### Step 4: Add Authentication to CRM (20 minutes)
- [ ] Add `requireAuth` function to `/api/crm/leads.js`
- [ ] Add authentication check at start of handler
- [ ] Test with valid token
- [ ] Test with invalid/missing token
- [ ] Deploy changes

### Step 5: Verify Fixes (10 minutes)
- [ ] Test login: `curl -X POST ... /login`
- [ ] Get token from response
- [ ] Test CRM with token: `curl -H "Authorization: Bearer <token>" ... /leads`
- [ ] Test contact form submission
- [ ] Verify emails are received

**Total Time:** ~60 minutes

---

## Post-Fix Testing Script

Save as `test-critical-fixes.sh`:

```bash
#!/bin/bash

API_BASE="https://api.jasperfinance.org"

echo "🧪 Testing Critical Fixes"
echo "=========================="
echo ""

# Test 1: Login
echo "1️⃣ Testing Login..."
LOGIN_RESPONSE=$(curl -s -X POST $API_BASE/api/v1/admin/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@jasperfinance.org","password":"Admin123!"}')

TOKEN=$(echo $LOGIN_RESPONSE | python3 -c "import sys, json; print(json.load(sys.stdin).get('access_token', ''))")

if [ -z "$TOKEN" ]; then
  echo "❌ FAIL: Login failed"
  echo "Response: $LOGIN_RESPONSE"
  exit 1
else
  echo "✅ PASS: Login successful"
fi

echo ""

# Test 2: Auth Me
echo "2️⃣ Testing Auth Me..."
ME_RESPONSE=$(curl -s $API_BASE/api/v1/admin/auth/me \
  -H "Authorization: Bearer $TOKEN")

if echo $ME_RESPONSE | grep -q '"email"'; then
  echo "✅ PASS: Auth validation working"
else
  echo "❌ FAIL: Auth validation failed"
  echo "Response: $ME_RESPONSE"
fi

echo ""

# Test 3: CRM with Auth
echo "3️⃣ Testing CRM with Authentication..."
CRM_RESPONSE=$(curl -s $API_BASE/api/v1/crm/leads \
  -H "Authorization: Bearer $TOKEN")

if echo $CRM_RESPONSE | grep -q '"success":true'; then
  echo "✅ PASS: CRM accessible with auth"
else
  echo "❌ FAIL: CRM auth check failed"
  echo "Response: $CRM_RESPONSE"
fi

echo ""

# Test 4: CRM without Auth (should fail)
echo "4️⃣ Testing CRM without Authentication (should fail)..."
UNAUTH_RESPONSE=$(curl -s $API_BASE/api/v1/crm/leads)

if echo $UNAUTH_RESPONSE | grep -q 'Authentication required\|Not authenticated'; then
  echo "✅ PASS: CRM properly protected"
else
  echo "⚠️  WARN: CRM may still be accessible without auth"
  echo "Response: $UNAUTH_RESPONSE"
fi

echo ""
echo "=========================="
echo "🎯 Critical Fixes Testing Complete"
```

Run with:
```bash
chmod +x test-critical-fixes.sh
./test-critical-fixes.sh
```

---

## Support Contacts

If you need help fixing these issues:

1. **Login Endpoint Issues**
   - Check Vercel deployment logs
   - Verify `req.body` is properly parsed
   - Test with Postman/Insomnia first

2. **Environment Variables**
   - Vercel dashboard: Settings → Environment Variables
   - Remember to redeploy after adding vars
   - Test in preview deployment first

3. **Database Setup**
   - Start with Vercel Postgres (easiest)
   - Migration guide: https://vercel.com/docs/storage/vercel-postgres
   - Or Neon: https://neon.tech/docs/get-started-with-neon

---

**Last Updated:** 2025-12-11
**Next Review:** After all fixes deployed
