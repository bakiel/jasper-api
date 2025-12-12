/**
 * JASPER Admin Auth - Consolidated Handler
 * Handles: login, google, client-id, me
 */
import { SignJWT, jwtVerify } from 'jose';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const LINKEDIN_CLIENT_ID = process.env.LINKEDIN_CLIENT_ID;
const LINKEDIN_CLIENT_SECRET = process.env.LINKEDIN_CLIENT_SECRET;
const LINKEDIN_REDIRECT_URI = process.env.LINKEDIN_REDIRECT_URI || 'https://portal.jasperfinance.org/login';
const SECRET_KEY = process.env.SECRET_KEY || 'jasper-default-secret-key-change-in-production';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@jasperfinance.org';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin123!';

function getSecretKey() {
  return new TextEncoder().encode(SECRET_KEY);
}

function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return Math.abs(hash);
}

async function createAdminToken(user, provider = 'password') {
  const expiresIn = 8 * 60 * 60;
  const token = await new SignJWT({
    sub: String(user.id),
    admin_id: user.id,
    email: user.email,
    role: user.role,
    type: 'admin',
    provider: provider
  })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('8h')
    .sign(getSecretKey());
  return { token, expiresIn };
}

function setCorsHeaders(req, res) {
  const allowedOrigins = ['https://jasperfinance.org', 'https://portal.jasperfinance.org', 'http://localhost:3000'];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
}

export default async function handler(req, res) {
  setCorsHeaders(req, res);

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  // Route to appropriate handler
  if (path.includes('/login')) {
    return handleLogin(req, res);
  } else if (path.includes('/client-id')) {
    return handleClientId(req, res);
  } else if (path.includes('/google') || path.includes('/linkedin')) {
    return handleOAuth(req, res);
  } else if (path.includes('/me')) {
    return handleMe(req, res);
  }

  return res.status(404).json({ detail: 'Admin auth endpoint not found' });
}

// ============ Email/Password Login ============
async function handleLogin(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }

  try {
    let body;
    if (req.body && typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      body = req.body;
    } else {
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
      } catch {
        try {
          body = JSON.parse(rawBody.replace(/\\!/g, '!'));
        } catch {
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
    const isValidCredentials = normalizedEmail === ADMIN_EMAIL.toLowerCase() && password === ADMIN_PASSWORD;

    if (!isValidCredentials) {
      console.warn(`Failed login attempt for: ${normalizedEmail}`);
      return res.status(401).json({ detail: 'Invalid email or password' });
    }

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

    const { token, expiresIn } = await createAdminToken(user);

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

// ============ Get Client ID ============
function handleClientId(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }

  const { provider } = req.query;

  if (provider === 'linkedin') {
    if (!LINKEDIN_CLIENT_ID) {
      return res.status(503).json({ detail: 'LinkedIn OAuth not configured' });
    }
    return res.status(200).json({
      client_id: LINKEDIN_CLIENT_ID,
      redirect_uri: LINKEDIN_REDIRECT_URI,
      scope: 'openid profile email'
    });
  }

  if (!GOOGLE_CLIENT_ID) {
    return res.status(503).json({ detail: 'Google OAuth not configured' });
  }
  return res.status(200).json({ client_id: GOOGLE_CLIENT_ID });
}

// ============ OAuth Login (Google/LinkedIn) ============
async function handleOAuth(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }

  try {
    const { provider, credential, code, redirect_uri } = req.body;

    // LinkedIn OAuth
    if (provider === 'linkedin' || code) {
      if (!code) {
        return res.status(400).json({ detail: 'Authorization code required for LinkedIn' });
      }

      if (!LINKEDIN_CLIENT_ID || !LINKEDIN_CLIENT_SECRET) {
        return res.status(503).json({ detail: 'LinkedIn OAuth not configured' });
      }

      const actualRedirectUri = redirect_uri || LINKEDIN_REDIRECT_URI;

      const tokenResponse = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          code: code,
          client_id: LINKEDIN_CLIENT_ID,
          client_secret: LINKEDIN_CLIENT_SECRET,
          redirect_uri: actualRedirectUri,
        }),
      });

      if (!tokenResponse.ok) {
        return res.status(401).json({ detail: 'Failed to exchange authorization code' });
      }

      const tokenData = await tokenResponse.json();
      const accessToken = tokenData.access_token;

      if (!accessToken) {
        return res.status(401).json({ detail: 'No access token received from LinkedIn' });
      }

      const userInfoResponse = await fetch('https://api.linkedin.com/v2/userinfo', {
        headers: { 'Authorization': `Bearer ${accessToken}` },
      });

      if (!userInfoResponse.ok) {
        return res.status(401).json({ detail: 'Failed to fetch LinkedIn user info' });
      }

      const userInfo = await userInfoResponse.json();
      const email = (userInfo.email || '').toLowerCase();

      if (!email || !userInfo.email_verified) {
        return res.status(401).json({ detail: 'LinkedIn email not verified' });
      }

      const user = {
        id: hashCode(email),
        email: email,
        first_name: userInfo.given_name || 'LinkedIn',
        last_name: userInfo.family_name || 'User',
        role: 'admin',
        is_active: true,
        email_verified: true,
        picture: userInfo.picture || '',
        auth_provider: 'linkedin'
      };

      const { token, expiresIn } = await createAdminToken(user, 'linkedin');
      return res.status(200).json({
        access_token: token,
        token_type: 'bearer',
        expires_in: expiresIn,
        user: user
      });
    }

    // Google OAuth (default)
    if (!credential) {
      return res.status(400).json({ detail: 'Google credential required' });
    }

    if (!GOOGLE_CLIENT_ID) {
      return res.status(503).json({ detail: 'Google OAuth not configured' });
    }

    const googleResponse = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`
    );

    if (!googleResponse.ok) {
      return res.status(401).json({ detail: 'Invalid Google token' });
    }

    const googleData = await googleResponse.json();

    if (googleData.aud !== GOOGLE_CLIENT_ID) {
      return res.status(401).json({ detail: 'Token not intended for this application' });
    }

    const email = (googleData.email || '').toLowerCase();
    const emailVerified = googleData.email_verified === true || googleData.email_verified === 'true';

    if (!email || !emailVerified) {
      return res.status(401).json({ detail: 'Email not verified with Google' });
    }

    const user = {
      id: hashCode(email),
      email: email,
      first_name: googleData.given_name || 'Google',
      last_name: googleData.family_name || 'User',
      role: 'admin',
      is_active: true,
      email_verified: true,
      auth_provider: 'google'
    };

    const { token, expiresIn } = await createAdminToken(user, 'google');
    return res.status(200).json({
      access_token: token,
      token_type: 'bearer',
      expires_in: expiresIn,
      user: user
    });

  } catch (error) {
    console.error('OAuth auth error:', error);
    return res.status(500).json({ detail: 'Authentication failed' });
  }
}

// ============ Get Current User ============
async function handleMe(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }

  try {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return res.status(401).json({ detail: 'Not authenticated' });
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      return res.status(401).json({ detail: 'Invalid authorization header' });
    }

    const token = parts[1];

    const { payload } = await jwtVerify(token, getSecretKey());

    if (payload.type !== 'admin') {
      return res.status(401).json({ detail: 'Invalid token type' });
    }

    return res.status(200).json({
      id: payload.admin_id,
      email: payload.email,
      first_name: payload.email?.split('@')[0] || 'User',
      last_name: '',
      role: payload.role,
      is_active: true,
      email_verified: true
    });

  } catch (error) {
    if (error.code === 'ERR_JWT_EXPIRED') {
      return res.status(401).json({ detail: 'Token expired' });
    }
    return res.status(401).json({ detail: 'Invalid token' });
  }
}
