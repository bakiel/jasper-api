/**
 * JASPER Admin Auth - Email/Password Login
 * Verifies credentials and returns JWT
 */
import { SignJWT } from 'jose';

const SECRET_KEY = process.env.SECRET_KEY || 'jasper-default-secret-key-change-in-production';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@jasperfinance.org';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin123!';

// Encode the secret key for jose
function getSecretKey() {
  return new TextEncoder().encode(SECRET_KEY);
}

// Simple hash function to generate consistent user ID from email
function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash);
}

export default async function handler(req, res) {
  // CORS headers - restrict to known origins
  const allowedOrigins = ['https://jasperfinance.org', 'https://portal.jasperfinance.org', 'http://localhost:3000'];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }

  try {
    // Handle both Express pre-parsed body and Vercel streaming body
    let body;

    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      // Express already parsed the body
      body = req.body;
    } else {
      // Vercel serverless - collect raw body from stream
      const chunks = [];
      for await (const chunk of req) {
        chunks.push(chunk);
      }
      const rawBody = Buffer.concat(chunks).toString('utf8');

      if (!rawBody || rawBody.trim() === '') {
        return res.status(400).json({ detail: 'Request body is required' });
      }

      try {
        body = JSON.parse(rawBody);
      } catch (parseError) {
        // Fix common escaping issues from edge proxies
        try {
          const fixedBody = rawBody.replace(/\\!/g, '!');
          body = JSON.parse(fixedBody);
        } catch (secondError) {
          return res.status(400).json({ detail: 'Invalid JSON in request body' });
        }
      }
    }

    const email = body.email;
    const password = body.password;

    if (!email || !password) {
      return res.status(400).json({ detail: 'Email and password required' });
    }

    const normalizedEmail = String(email).toLowerCase().trim();

    // Check admin credentials - no fallback, strict validation only
    const isValidCredentials = normalizedEmail === ADMIN_EMAIL.toLowerCase() && password === ADMIN_PASSWORD;

    if (!isValidCredentials) {
      // Log failed attempt for security monitoring
      console.warn(`Failed login attempt for: ${normalizedEmail} from IP: ${req.headers['x-forwarded-for'] || 'unknown'}`);
      return res.status(401).json({ detail: 'Invalid email or password' });
    }

    // Create admin user object
    const user = {
      id: hashCode(normalizedEmail),
      email: normalizedEmail,
      first_name: normalizedEmail.split('@')[0].charAt(0).toUpperCase() + normalizedEmail.split('@')[0].slice(1),
      last_name: '',
      role: 'admin',
      is_active: true,
      email_verified: true,
      last_login: new Date().toISOString(),
      created_at: new Date().toISOString()
    };

    // Generate JWT
    const expiresIn = 8 * 60 * 60; // 8 hours
    const token = await new SignJWT({
      sub: String(user.id),
      admin_id: user.id,
      email: user.email,
      role: user.role,
      type: 'admin'
    })
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('8h')
      .sign(getSecretKey());

    return res.status(200).json({
      access_token: token,
      token_type: 'bearer',
      expires_in: expiresIn,
      user: user
    });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ detail: 'Authentication failed' });
  }
}
