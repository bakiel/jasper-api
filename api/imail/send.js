import nodemailer from 'nodemailer';

// Rate limiting
const rateLimitMap = new Map();
const RATE_LIMIT = 10;
const RATE_WINDOW = 60 * 1000; // 1 minute

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip);
  if (!record || now - record.timestamp > RATE_WINDOW) {
    rateLimitMap.set(ip, { count: 1, timestamp: now });
    return true;
  }
  if (record.count >= RATE_LIMIT) return false;
  record.count++;
  return true;
}

// Email transporter
function getTransporter() {
  return nodemailer.createTransport({
    host: process.env.SMTP_HOST || 'smtp.hostinger.com',
    port: parseInt(process.env.SMTP_PORT) || 587,
    secure: false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });
}

// Generate tracking ID
function generateTrackingId() {
  return `JIM-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`;
}

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, error: 'Method not allowed' });
  }

  // API Key verification
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  if (apiKey !== process.env.IMAIL_API_KEY) {
    return res.status(401).json({ success: false, error: 'Invalid API key' });
  }

  // Rate limit
  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    return res.status(429).json({ success: false, error: 'Rate limit exceeded' });
  }

  try {
    const { to, subject, template, data, html, text, from, replyTo } = req.body;

    // Validation
    if (!to) return res.status(400).json({ success: false, error: 'Recipient (to) is required' });
    if (!subject) return res.status(400).json({ success: false, error: 'Subject is required' });
    if (!template && !html && !text) {
      return res.status(400).json({ success: false, error: 'Template, HTML, or text content required' });
    }

    // Normalize recipients
    const recipients = Array.isArray(to) ? to : [to];
    const trackingId = generateTrackingId();

    // Get template content or use provided
    let emailHtml = html;
    let emailText = text;

    if (template) {
      const templateContent = getTemplate(template, data);
      emailHtml = templateContent.html;
      emailText = templateContent.text;
    }

    const transporter = getTransporter();
    const results = [];

    for (const recipient of recipients) {
      try {
        const info = await transporter.sendMail({
          from: from || `"JASPER Financial" <${process.env.SMTP_USER}>`,
          to: recipient,
          replyTo: replyTo || process.env.SMTP_USER,
          subject,
          html: emailHtml,
          text: emailText,
          headers: {
            'X-JASPER-Tracking-ID': trackingId,
            'X-Mailer': 'JASPER iMail EMV'
          }
        });

        results.push({
          recipient,
          status: 'sent',
          messageId: info.messageId
        });
      } catch (err) {
        results.push({
          recipient,
          status: 'failed',
          error: err.message
        });
      }
    }

    const successCount = results.filter(r => r.status === 'sent').length;

    return res.status(200).json({
      success: successCount > 0,
      trackingId,
      sent: successCount,
      failed: results.length - successCount,
      results
    });

  } catch (error) {
    console.error('iMail send error:', error);
    return res.status(500).json({
      success: false,
      error: 'Internal server error'
    });
  }
}

// Template system
function getTemplate(templateName, data = {}) {
  const templates = {
    'welcome': {
      html: getWelcomeTemplate(data),
      text: `Welcome to JASPER Financial, ${data.name || 'Client'}!`
    },
    'notification': {
      html: getNotificationTemplate(data),
      text: data.message || 'You have a new notification from JASPER.'
    },
    'verification': {
      html: getVerificationTemplate(data),
      text: `Your verification code is: ${data.code || '------'}`
    },
    'invoice': {
      html: getInvoiceTemplate(data),
      text: `Invoice ${data.invoiceNumber || 'N/A'} - Amount: ${data.amount || 'R0.00'}`
    }
  };

  return templates[templateName] || { html: '', text: '' };
}

// Logo URLs - hosted on API domain
const LOGO_URL = 'https://jasper-api.vercel.app/logo.png';
const ICON_URL = 'https://jasper-api.vercel.app/icon.png';

function getWelcomeTemplate(data) {
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#050A14;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#050A14;padding:40px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#0B1221;border-radius:16px;border:1px solid rgba(44,138,91,0.2);">
<tr><td style="background:linear-gradient(135deg,#0B1221,#132337);padding:40px;text-align:center;border-bottom:1px solid rgba(44,138,91,0.3);">
<img src="${ICON_URL}" alt="JASPER" width="60" style="max-width:60px;height:auto;margin-bottom:12px;" />
<h1 style="color:#2C8A5B;font-size:28px;margin:0;font-weight:700;">JASPER</h1>
<p style="color:#64748B;font-size:12px;margin:8px 0 0;letter-spacing:2px;">FINANCIAL ARCHITECTURE</p>
</td></tr>
<tr><td style="padding:40px;">
<h2 style="color:#F8FAFC;font-size:22px;margin:0 0 16px;">Welcome, ${data.name || 'Valued Client'}</h2>
<p style="color:#94A3B8;font-size:15px;line-height:1.7;margin:0 0 24px;">
${data.message || 'Thank you for choosing JASPER Financial Architecture. We are excited to partner with you on your financial journey.'}
</p>
${data.cta ? `
<a href="${data.ctaUrl || '#'}" style="display:inline-block;background:#2C8A5B;color:#fff;padding:14px 28px;border-radius:8px;text-decoration:none;font-weight:600;">${data.cta}</a>
` : ''}
</td></tr>
<tr><td style="background:#050A14;padding:24px 40px;border-top:1px solid rgba(44,138,91,0.1);text-align:center;">
<p style="color:#64748B;font-size:13px;margin:0 0 8px;">JASPER Financial Architecture</p>
<p style="color:#475569;font-size:12px;margin:0;">
<a href="https://jasperfinance.org" style="color:#2C8A5B;text-decoration:none;">jasperfinance.org</a>
</p>
</td></tr>
</table>
</td></tr></table>
</body></html>`;
}

function getNotificationTemplate(data) {
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#050A14;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#050A14;padding:40px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#0B1221;border-radius:16px;border:1px solid rgba(44,138,91,0.2);">
<tr><td style="background:linear-gradient(135deg,#0B1221,#132337);padding:32px 40px;text-align:center;border-bottom:1px solid rgba(44,138,91,0.3);">
<img src="${ICON_URL}" alt="JASPER" width="50" style="max-width:50px;height:auto;margin-bottom:10px;" />
<h1 style="color:#2C8A5B;font-size:24px;margin:0;font-weight:700;">JASPER</h1>
<p style="color:#64748B;font-size:11px;margin:6px 0 0;letter-spacing:1px;">FINANCIAL ARCHITECTURE</p>
</td></tr>
<tr><td style="padding:40px;">
<div style="background:rgba(44,138,91,0.1);border-left:4px solid #2C8A5B;padding:20px;border-radius:0 8px 8px 0;margin-bottom:24px;">
<p style="color:#F8FAFC;font-size:15px;margin:0;line-height:1.6;">${data.message || 'You have a new notification.'}</p>
</div>
${data.details ? `<p style="color:#94A3B8;font-size:14px;line-height:1.6;">${data.details}</p>` : ''}
</td></tr>
<tr><td style="background:#050A14;padding:20px 40px;border-top:1px solid rgba(44,138,91,0.1);text-align:center;">
<p style="color:#475569;font-size:12px;margin:0;">
<a href="https://jasperfinance.org" style="color:#2C8A5B;text-decoration:none;">jasperfinance.org</a>
</p>
</td></tr>
</table>
</td></tr></table>
</body></html>`;
}

function getVerificationTemplate(data) {
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#050A14;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#050A14;padding:40px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#0B1221;border-radius:16px;border:1px solid rgba(44,138,91,0.2);">
<tr><td style="background:linear-gradient(135deg,#0B1221,#132337);padding:32px 40px;text-align:center;border-bottom:1px solid rgba(44,138,91,0.3);">
<img src="${ICON_URL}" alt="JASPER" width="50" style="max-width:50px;height:auto;margin-bottom:10px;" />
<h1 style="color:#2C8A5B;font-size:24px;margin:0;font-weight:700;">JASPER</h1>
<p style="color:#64748B;font-size:11px;margin:6px 0 0;letter-spacing:1px;">EMAIL VERIFICATION</p>
</td></tr>
<tr><td style="padding:40px;text-align:center;">
<p style="color:#94A3B8;font-size:15px;margin:0 0 24px;">Your verification code is:</p>
<div style="background:#0F172A;border:2px solid #2C8A5B;border-radius:12px;padding:24px;display:inline-block;">
<span style="color:#2C8A5B;font-size:32px;font-weight:bold;letter-spacing:8px;font-family:monospace;">${data.code || '------'}</span>
</div>
<p style="color:#64748B;font-size:13px;margin:24px 0 0;">This code expires in ${data.expiresIn || '10 minutes'}.</p>
</td></tr>
<tr><td style="background:#050A14;padding:20px 40px;border-top:1px solid rgba(44,138,91,0.1);text-align:center;">
<p style="color:#475569;font-size:12px;margin:0;">If you didn't request this code, please ignore this email.</p>
</td></tr>
</table>
</td></tr></table>
</body></html>`;
}

function getInvoiceTemplate(data) {
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#050A14;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#050A14;padding:40px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#0B1221;border-radius:16px;border:1px solid rgba(44,138,91,0.2);">
<tr><td style="background:linear-gradient(135deg,#0B1221,#132337);padding:32px 40px;border-bottom:1px solid rgba(44,138,91,0.3);">
<table width="100%"><tr>
<td><table cellpadding="0" cellspacing="0"><tr>
<td style="vertical-align:middle;"><img src="${ICON_URL}" alt="JASPER" width="40" style="max-width:40px;height:auto;" /></td>
<td style="vertical-align:middle;padding-left:12px;"><h1 style="color:#2C8A5B;font-size:22px;margin:0;font-weight:700;">JASPER</h1><p style="color:#64748B;font-size:10px;margin:2px 0 0;letter-spacing:1px;">FINANCIAL ARCHITECTURE</p></td>
</tr></table></td>
<td align="right"><span style="background:rgba(44,138,91,0.15);color:#2C8A5B;padding:8px 16px;border-radius:20px;font-size:12px;font-weight:600;">INVOICE</span></td>
</tr></table>
</td></tr>
<tr><td style="padding:32px 40px;">
<table width="100%" style="margin-bottom:24px;">
<tr>
<td><p style="color:#64748B;font-size:12px;margin:0;">Invoice Number</p><p style="color:#F8FAFC;font-size:16px;margin:4px 0 0;font-weight:600;">${data.invoiceNumber || 'N/A'}</p></td>
<td align="right"><p style="color:#64748B;font-size:12px;margin:0;">Date</p><p style="color:#F8FAFC;font-size:16px;margin:4px 0 0;">${data.date || new Date().toLocaleDateString()}</p></td>
</tr>
</table>
<div style="background:#0F172A;border-radius:8px;padding:20px;margin-bottom:24px;">
<p style="color:#64748B;font-size:12px;margin:0 0 8px;">Bill To</p>
<p style="color:#F8FAFC;font-size:15px;margin:0;line-height:1.6;">${data.clientName || 'Client'}<br>${data.clientEmail || ''}</p>
</div>
<table width="100%" style="border-collapse:collapse;">
<tr style="border-bottom:1px solid rgba(44,138,91,0.2);">
<td style="padding:12px 0;color:#64748B;font-size:12px;">DESCRIPTION</td>
<td style="padding:12px 0;color:#64748B;font-size:12px;text-align:right;">AMOUNT</td>
</tr>
${(data.items || [{ description: 'Professional Services', amount: data.amount || 'R0.00' }]).map(item => `
<tr style="border-bottom:1px solid rgba(44,138,91,0.1);">
<td style="padding:16px 0;color:#F8FAFC;font-size:14px;">${item.description}</td>
<td style="padding:16px 0;color:#F8FAFC;font-size:14px;text-align:right;">${item.amount}</td>
</tr>
`).join('')}
<tr>
<td style="padding:20px 0;color:#F8FAFC;font-size:16px;font-weight:600;">Total</td>
<td style="padding:20px 0;color:#2C8A5B;font-size:20px;font-weight:bold;text-align:right;">${data.total || data.amount || 'R0.00'}</td>
</tr>
</table>
</td></tr>
<tr><td style="background:#050A14;padding:20px 40px;border-top:1px solid rgba(44,138,91,0.1);text-align:center;">
<p style="color:#64748B;font-size:13px;margin:0 0 8px;">Payment due by ${data.dueDate || 'N/A'}</p>
<p style="color:#475569;font-size:12px;margin:0;">
<a href="https://jasperfinance.org" style="color:#2C8A5B;text-decoration:none;">jasperfinance.org</a>
</p>
</td></tr>
</table>
</td></tr></table>
</body></html>`;
}
