# JASPER Contact API

Serverless contact form API for JASPER Financial Architecture.

## Stack
- Vercel Serverless Functions
- Nodemailer for Hostinger SMTP
- No database (email-only for now)

## Endpoints

### Health Check
```
GET /health
```

### Contact Form
```
POST /contact
Content-Type: application/json

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

## Environment Variables

Set these in Vercel Dashboard:

```
SMTP_HOST=smtp.hostinger.com
SMTP_PORT=587
SMTP_USER=models@jasperfinance.org
SMTP_PASS=your_email_password
ADMIN_EMAIL=models@jasperfinance.org
```

## Deploy

```bash
npm i -g vercel
vercel login
vercel --prod
```

Then add custom domain `api.jasperfinance.org` in Vercel Dashboard.
