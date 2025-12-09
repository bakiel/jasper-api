# JASPER API

Serverless API for JASPER Financial Architecture, including Contact Form and iMail EMV (Enterprise Messaging & Verification).

## Base URL
```
https://jasper-api.vercel.app
```

## Endpoints

### Health Check
```
GET /health
```
Returns service status.

---

### Contact Form
```
POST /contact
Content-Type: application/json
Origin: https://jasperfinance.org

{
  "name": "John Doe",
  "email": "john@company.com",
  "company": "Company Ltd",
  "sector": "renewable-energy",
  "fundingStage": "series-a",
  "fundingAmount": "15-75m",
  "message": "Project description...",
  "phone": "+27 12 345 6789"
}
```

---

## iMail EMV API

Enterprise email system with verification, templates, and tracking.

### Authentication
All iMail endpoints require API key authentication:
```
X-API-Key: your_api_key
```
Or:
```
Authorization: Bearer your_api_key
```

---

### Send Email
```
POST /imail/send
```

**Request:**
```json
{
  "to": "recipient@example.com",
  "subject": "Email Subject",
  "template": "welcome",
  "data": {
    "name": "John",
    "message": "Custom message",
    "cta": "View Dashboard",
    "ctaUrl": "https://jasperfinance.org"
  }
}
```

**Available Templates:**
- `welcome` - Welcome emails with CTA button
- `notification` - General notifications
- `verification` - OTP/verification codes
- `invoice` - Invoice emails

**Custom HTML/Text:**
```json
{
  "to": ["email1@example.com", "email2@example.com"],
  "subject": "Custom Email",
  "html": "<h1>Hello</h1><p>Custom HTML content</p>",
  "text": "Plain text fallback"
}
```

**Response:**
```json
{
  "success": true,
  "trackingId": "JIM-ABC123XY-1234",
  "sent": 1,
  "failed": 0,
  "results": [
    {
      "recipient": "recipient@example.com",
      "status": "sent",
      "messageId": "<message-id@jasperfinance.org>"
    }
  ]
}
```

---

### Verify Email
```
POST /imail/verify
```

**Request:**
```json
{
  "email": "test@gmail.com",
  "checkMx": true,
  "checkDisposable": true
}
```

**Response:**
```json
{
  "success": true,
  "email": "test@gmail.com",
  "valid": true,
  "checks": {
    "format": true,
    "localPart": true,
    "domain": true,
    "disposable": true,
    "mx": true
  },
  "mxRecords": ["gmail-smtp-in.l.google.com", "..."],
  "riskScore": 0,
  "riskLevel": "low",
  "suggestions": []
}
```

---

### Email Status
```
GET /imail/status?trackingId=JIM-ABC123XY-1234
POST /imail/status
```

**GET** - Retrieve delivery status by tracking ID

**POST** - Update status (for webhook receivers)
```json
{
  "trackingId": "JIM-ABC123XY-1234",
  "event": "delivered",
  "recipient": "user@example.com",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

**Events:** `sent`, `delivered`, `opened`, `clicked`, `bounced`, `complained`, `unsubscribed`

---

## Environment Variables

Set in Vercel Dashboard:

```env
# SMTP Configuration
SMTP_HOST=smtp.hostinger.com
SMTP_PORT=587
SMTP_USER=models@jasperfinance.org
SMTP_PASS=your_password

# Admin
ADMIN_EMAIL=models@jasperfinance.org

# iMail EMV
IMAIL_API_KEY=jsp_imail_xxx
IMAIL_WEBHOOK_SECRET=jsp_whsec_xxx
IMAIL_WEBHOOK_URL=https://your-app.com/webhooks/email  # Optional
```

---

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| /contact | 5 requests | 15 minutes |
| /imail/send | 10 requests | 1 minute |
| /imail/verify | 20 requests | 1 minute |

---

## Deployment

```bash
npm i -g vercel
vercel login
vercel --prod
```

Custom domain: `api.jasperfinance.org` (configure in Vercel Dashboard)

---

## Stack
- Vercel Serverless Functions
- Nodemailer for SMTP
- No database (stateless)
