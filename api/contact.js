import nodemailer from 'nodemailer';

// Rate limiting using Map (resets per instance, good enough for serverless)
const rateLimitMap = new Map();
const RATE_LIMIT = 5; // requests per IP
const RATE_WINDOW = 15 * 60 * 1000; // 15 minutes

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip);

  if (!record || now - record.timestamp > RATE_WINDOW) {
    rateLimitMap.set(ip, { count: 1, timestamp: now });
    return true;
  }

  if (record.count >= RATE_LIMIT) {
    return false;
  }

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

// Email templates
function getAdminEmailHTML(data, reference) {
  const sectorLabels = {
    'renewable-energy': 'Renewable Energy',
    'data-centres': 'Data Centres',
    'agri-industrial': 'Agri-Industrial',
    'climate-finance': 'Climate Finance',
    'technology': 'Technology',
    'manufacturing': 'Manufacturing',
    'other': 'Other'
  };
  const stageLabels = {
    'seed': 'Seed / Pre-Revenue',
    'series-a': 'Series A',
    'series-b': 'Series B',
    'growth': 'Growth Stage',
    'expansion': 'Expansion',
    'other': 'Other'
  };

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
<td><h1 style="color:#2C8A5B;font-size:24px;margin:0;">JASPER</h1><p style="color:#64748B;font-size:12px;margin:4px 0 0;letter-spacing:1px;">FINANCIAL ARCHITECTURE</p></td>
<td align="right"><span style="background:rgba(44,138,91,0.15);color:#2C8A5B;padding:8px 16px;border-radius:20px;font-size:12px;font-weight:600;">NEW LEAD</span></td>
</tr></table>
</td></tr>
<tr><td style="padding:24px 40px 0;">
<p style="color:#64748B;font-size:13px;margin:0;">Reference</p>
<p style="color:#F8FAFC;font-size:18px;margin:4px 0 0;font-weight:600;">${reference}</p>
</td></tr>
<tr><td style="padding:24px 40px;">
<table width="100%" style="background:rgba(44,138,91,0.05);border-radius:12px;border:1px solid rgba(44,138,91,0.1);padding:24px;">
<tr><td width="50%" style="padding:8px 0;"><p style="color:#64748B;font-size:11px;margin:0;text-transform:uppercase;">Contact</p><p style="color:#F8FAFC;font-size:15px;margin:4px 0 0;">${data.name}</p></td>
<td width="50%" style="padding:8px 0;"><p style="color:#64748B;font-size:11px;margin:0;text-transform:uppercase;">Company</p><p style="color:#F8FAFC;font-size:15px;margin:4px 0 0;">${data.company}</p></td></tr>
<tr><td style="padding:8px 0;"><p style="color:#64748B;font-size:11px;margin:0;text-transform:uppercase;">Email</p><p style="color:#2C8A5B;font-size:15px;margin:4px 0 0;">${data.email}</p></td>
<td style="padding:8px 0;"><p style="color:#64748B;font-size:11px;margin:0;text-transform:uppercase;">Phone</p><p style="color:#F8FAFC;font-size:15px;margin:4px 0 0;">${data.phone || 'N/A'}</p></td></tr>
<tr><td style="padding:8px 0;"><p style="color:#64748B;font-size:11px;margin:0;text-transform:uppercase;">Sector</p><p style="color:#F8FAFC;font-size:15px;margin:4px 0 0;">${sectorLabels[data.sector] || data.sector}</p></td>
<td style="padding:8px 0;"><p style="color:#64748B;font-size:11px;margin:0;text-transform:uppercase;">Funding Stage</p><p style="color:#F8FAFC;font-size:15px;margin:4px 0 0;">${stageLabels[data.fundingStage] || data.fundingStage}</p></td></tr>
${data.fundingAmount ? `<tr><td colspan="2" style="padding:8px 0;"><p style="color:#64748B;font-size:11px;margin:0;text-transform:uppercase;">Funding Amount</p><p style="color:#F8FAFC;font-size:15px;margin:4px 0 0;">${data.fundingAmount}</p></td></tr>` : ''}
</table>
</td></tr>
<tr><td style="padding:0 40px 32px;">
<p style="color:#64748B;font-size:11px;margin:0 0 8px;text-transform:uppercase;">Message</p>
<div style="background:#0F172A;border-radius:8px;padding:20px;border-left:3px solid #2C8A5B;">
<p style="color:#CBD5E1;font-size:14px;margin:0;line-height:1.6;white-space:pre-wrap;">${data.message}</p>
</div>
</td></tr>
<tr><td style="background:#050A14;padding:20px 40px;border-top:1px solid rgba(44,138,91,0.1);">
<p style="color:#475569;font-size:12px;margin:0;">Submitted: ${new Date().toISOString()}</p>
</td></tr>
</table>
</td></tr></table>
</body></html>`;
}

function getClientEmailHTML(data) {
  return `
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:#050A14;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#050A14;padding:40px 20px;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="background:#0B1221;border-radius:16px;border:1px solid rgba(44,138,91,0.2);">
<tr><td style="background:linear-gradient(135deg,#0B1221,#132337);padding:40px;text-align:center;border-bottom:1px solid rgba(44,138,91,0.3);">
<h1 style="color:#2C8A5B;font-size:28px;margin:0;">JASPER</h1>
<p style="color:#64748B;font-size:12px;margin:8px 0 0;letter-spacing:2px;">FINANCIAL ARCHITECTURE</p>
</td></tr>
<tr><td style="padding:40px;">
<h2 style="color:#F8FAFC;font-size:22px;margin:0 0 16px;">Thank you, ${data.name}</h2>
<p style="color:#94A3B8;font-size:15px;line-height:1.7;margin:0 0 24px;">
We've received your enquiry and our team is reviewing your project requirements.
You can expect to hear from us within <strong style="color:#F8FAFC;">24 hours</strong>.
</p>
<div style="background:rgba(44,138,91,0.08);border-radius:12px;padding:24px;border:1px solid rgba(44,138,91,0.15);margin:24px 0;">
<h3 style="color:#2C8A5B;font-size:14px;margin:0 0 16px;text-transform:uppercase;letter-spacing:1px;">What happens next?</h3>
<p style="color:#CBD5E1;font-size:14px;margin:8px 0;"><span style="color:#2C8A5B;font-weight:bold;">1.</span> We review your project scope and requirements</p>
<p style="color:#CBD5E1;font-size:14px;margin:8px 0;"><span style="color:#2C8A5B;font-weight:bold;">2.</span> A consultant will reach out to schedule a discovery call</p>
<p style="color:#CBD5E1;font-size:14px;margin:8px 0;"><span style="color:#2C8A5B;font-weight:bold;">3.</span> You receive a tailored proposal based on your needs</p>
</div>
<p style="color:#64748B;font-size:14px;line-height:1.6;margin:24px 0 0;">
Feel free to reply to this email if you have any additional information to share.
</p>
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

export default async function handler(req, res) {
  // CORS preflight
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', 'https://jasperfinance.org');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(200).end();
  }

  // Only POST
  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method not allowed' });
  }

  // Rate limiting
  const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
  if (!checkRateLimit(ip)) {
    return res.status(429).json({
      success: false,
      message: 'Too many requests. Please try again in 15 minutes.'
    });
  }

  try {
    const { name, email, company, sector, fundingStage, fundingAmount, message, phone } = req.body;

    // Validation
    const errors = {};
    if (!name?.trim()) errors.name = 'Name is required';
    if (!email?.trim() || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = 'Valid email is required';
    if (!company?.trim()) errors.company = 'Company is required';
    if (!sector?.trim()) errors.sector = 'Sector is required';
    if (!fundingStage?.trim()) errors.fundingStage = 'Funding stage is required';
    if (!message?.trim() || message.length < 20) errors.message = 'Message must be at least 20 characters';

    if (Object.keys(errors).length > 0) {
      return res.status(422).json({ success: false, message: 'Validation failed', errors });
    }

    // Sanitize
    const sanitize = (str) => str?.trim().replace(/[<>]/g, '') || '';
    const data = {
      name: sanitize(name),
      email: sanitize(email).toLowerCase(),
      company: sanitize(company),
      sector: sanitize(sector),
      fundingStage: sanitize(fundingStage),
      fundingAmount: sanitize(fundingAmount),
      message: sanitize(message),
      phone: sanitize(phone)
    };

    const reference = `JSP-${Date.now().toString(36).toUpperCase()}`;
    const transporter = getTransporter();

    // Send admin notification
    try {
      await transporter.sendMail({
        from: `"JASPER Financial" <${process.env.SMTP_USER}>`,
        to: process.env.ADMIN_EMAIL || process.env.SMTP_USER,
        subject: `New Lead: ${data.company} - ${reference}`,
        html: getAdminEmailHTML(data, reference)
      });
    } catch (emailError) {
      console.error('Admin email error:', emailError.message);
    }

    // Send client auto-reply
    try {
      await transporter.sendMail({
        from: `"JASPER Financial" <${process.env.SMTP_USER}>`,
        to: data.email,
        subject: 'Thank you for contacting JASPER Financial',
        html: getClientEmailHTML(data)
      });
    } catch (emailError) {
      console.error('Client email error:', emailError.message);
    }

    res.setHeader('Access-Control-Allow-Origin', 'https://jasperfinance.org');
    return res.status(200).json({
      success: true,
      message: "Thank you for your enquiry. We'll be in touch within 24 hours.",
      reference
    });

  } catch (error) {
    console.error('Contact error:', error);
    return res.status(500).json({
      success: false,
      message: 'An error occurred. Please email us directly at models@jasperfinance.org'
    });
  }
}
