import dns from 'dns';
import { promisify } from 'util';

const resolveMx = promisify(dns.resolveMx);

// Rate limiting
const rateLimitMap = new Map();
const RATE_LIMIT = 20;
const RATE_WINDOW = 60 * 1000;

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

// Disposable email domains
const disposableDomains = new Set([
  'tempmail.com', 'throwaway.email', 'guerrillamail.com', 'mailinator.com',
  'temp-mail.org', '10minutemail.com', 'fakeinbox.com', 'trashmail.com',
  'yopmail.com', 'getnada.com', 'dispostable.com', 'sharklasers.com'
]);

// Common typos
const domainTypos = {
  'gmial.com': 'gmail.com',
  'gmal.com': 'gmail.com',
  'gamil.com': 'gmail.com',
  'gnail.com': 'gmail.com',
  'gmail.co': 'gmail.com',
  'gmail.con': 'gmail.com',
  'hotmal.com': 'hotmail.com',
  'hotmai.com': 'hotmail.com',
  'hotmail.co': 'hotmail.com',
  'outlok.com': 'outlook.com',
  'outloo.com': 'outlook.com',
  'yahooo.com': 'yahoo.com',
  'yaho.com': 'yahoo.com'
};

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
    const { email, checkMx = true, checkDisposable = true } = req.body;

    if (!email) {
      return res.status(400).json({ success: false, error: 'Email is required' });
    }

    const result = await verifyEmail(email, { checkMx, checkDisposable });

    return res.status(200).json({
      success: true,
      ...result
    });

  } catch (error) {
    console.error('Email verification error:', error);
    return res.status(500).json({
      success: false,
      error: 'Verification failed'
    });
  }
}

async function verifyEmail(email, options = {}) {
  const { checkMx = true, checkDisposable = true } = options;
  const result = {
    email: email.toLowerCase().trim(),
    valid: false,
    checks: {},
    suggestions: []
  };

  // Format check
  const emailRegex = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  result.checks.format = emailRegex.test(result.email);

  if (!result.checks.format) {
    result.reason = 'Invalid email format';
    return result;
  }

  const [localPart, domain] = result.email.split('@');

  // Local part checks
  result.checks.localPart = localPart.length >= 1 && localPart.length <= 64;

  // Domain checks
  result.checks.domain = domain.length >= 3 && domain.includes('.');

  // Check for typos
  if (domainTypos[domain]) {
    result.suggestions.push({
      type: 'typo',
      message: `Did you mean ${localPart}@${domainTypos[domain]}?`,
      suggested: `${localPart}@${domainTypos[domain]}`
    });
  }

  // Disposable check
  if (checkDisposable) {
    result.checks.disposable = !disposableDomains.has(domain);
    if (!result.checks.disposable) {
      result.suggestions.push({
        type: 'disposable',
        message: 'This appears to be a disposable email address'
      });
    }
  }

  // MX record check
  if (checkMx) {
    try {
      const mxRecords = await resolveMx(domain);
      result.checks.mx = mxRecords && mxRecords.length > 0;
      if (result.checks.mx) {
        result.mxRecords = mxRecords.sort((a, b) => a.priority - b.priority).map(r => r.exchange);
      }
    } catch (err) {
      result.checks.mx = false;
      result.suggestions.push({
        type: 'mx',
        message: 'Could not verify domain email server'
      });
    }
  }

  // Calculate overall validity
  const requiredChecks = ['format', 'localPart', 'domain'];
  if (checkMx) requiredChecks.push('mx');
  if (checkDisposable) requiredChecks.push('disposable');

  result.valid = requiredChecks.every(check => result.checks[check] === true);

  if (!result.valid && !result.reason) {
    const failedChecks = requiredChecks.filter(check => !result.checks[check]);
    result.reason = `Failed checks: ${failedChecks.join(', ')}`;
  }

  // Risk score (0-100, lower is better)
  let riskScore = 0;
  if (!result.checks.mx) riskScore += 40;
  if (!result.checks.disposable) riskScore += 30;
  if (result.suggestions.some(s => s.type === 'typo')) riskScore += 20;
  if (localPart.includes('+')) riskScore += 5; // Plus addressing
  if (/^\d+$/.test(localPart)) riskScore += 10; // All numbers

  result.riskScore = Math.min(riskScore, 100);
  result.riskLevel = riskScore <= 10 ? 'low' : riskScore <= 40 ? 'medium' : 'high';

  return result;
}
