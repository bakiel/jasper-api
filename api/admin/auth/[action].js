// Consolidated admin auth endpoint - handles all admin auth routes
import { OAuth2Client } from 'google-auth-library';

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { action } = req.query;

  // Route to appropriate handler
  switch (action) {
    case 'login':
      return handleLogin(req, res);
    case 'google':
      return handleGoogle(req, res);
    case 'google-client-id':
      return handleGoogleClientId(req, res);
    case 'linkedin':
      return handleLinkedIn(req, res);
    case 'linkedin-client-id':
      return handleLinkedInClientId(req, res);
    case 'me':
      return handleMe(req, res);
    default:
      return res.status(404).json({ error: 'Not found' });
  }
}

// Email/password login - simple demo auth
async function handleLogin(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ detail: 'Email and password required' });
  }

  // Demo credentials - in production this would check a database
  const validUsers = {
    'admin@jasperfinance.org': { password: 'Admin123!', name: 'Admin User' },
    'bakielisrael@gmail.com': { password: 'Admin123!', name: 'Bakiel Nxumalo' },
  };

  const user = validUsers[email.toLowerCase()];
  if (!user || user.password !== password) {
    return res.status(401).json({ detail: 'Invalid email or password' });
  }

  const sessionData = {
    id: email,
    email: email.toLowerCase(),
    name: user.name,
    picture: '',
    exp: Date.now() + (7 * 24 * 60 * 60 * 1000),
  };

  const accessToken = Buffer.from(JSON.stringify(sessionData)).toString('base64');

  return res.status(200).json({
    access_token: accessToken,
    token_type: 'Bearer',
    expires_in: 604800,
    user: {
      id: 1,
      email: email.toLowerCase(),
      first_name: user.name.split(' ')[0] || '',
      last_name: user.name.split(' ').slice(1).join(' ') || '',
      role: 'admin',
      is_active: true,
      email_verified: true,
      last_login: new Date().toISOString(),
      created_at: new Date().toISOString(),
    },
  });
}

// Google OAuth client ID
async function handleGoogleClientId(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    return res.status(500).json({ error: 'Google OAuth not configured' });
  }
  return res.status(200).json({ client_id: clientId });
}

// Google OAuth login
async function handleGoogle(req, res) {
  if (req.method === 'GET') {
    return handleGoogleClientId(req, res);
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ detail: 'Credential required' });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    const sessionData = {
      id: googleId,
      email,
      name,
      picture,
      exp: Date.now() + (7 * 24 * 60 * 60 * 1000),
    };

    const accessToken = Buffer.from(JSON.stringify(sessionData)).toString('base64');

    const user = {
      id: 1,
      email,
      first_name: name?.split(' ')[0] || '',
      last_name: name?.split(' ').slice(1).join(' ') || '',
      role: 'admin',
      is_active: true,
      email_verified: true,
      last_login: new Date().toISOString(),
      created_at: new Date().toISOString(),
    };

    return res.status(200).json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 604800,
      user,
    });
  } catch (error) {
    console.error('Google auth error:', error);
    return res.status(401).json({ detail: 'Invalid Google credential' });
  }
}

// LinkedIn OAuth client config
async function handleLinkedInClientId(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  const clientId = process.env.LINKEDIN_CLIENT_ID;
  if (!clientId) {
    return res.status(500).json({ error: 'LinkedIn OAuth not configured' });
  }
  return res.status(200).json({
    client_id: clientId,
    redirect_uri: 'https://portal.jasperfinance.org/login',
    scope: 'openid profile email',
  });
}

// LinkedIn OAuth login
async function handleLinkedIn(req, res) {
  if (req.method === 'GET') {
    return handleLinkedInClientId(req, res);
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { code, redirect_uri } = req.body;

    if (!code) {
      return res.status(400).json({ detail: 'Code required' });
    }

    const clientId = process.env.LINKEDIN_CLIENT_ID;
    const clientSecret = process.env.LINKEDIN_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      return res.status(500).json({ detail: 'LinkedIn OAuth not configured' });
    }

    const tokenResponse = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirect_uri || 'https://portal.jasperfinance.org/login',
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });

    const tokens = await tokenResponse.json();

    if (tokens.error) {
      console.error('LinkedIn token error:', tokens);
      return res.status(401).json({
        detail: 'LinkedIn authentication failed',
        error: tokens.error_description || tokens.error
      });
    }

    const userResponse = await fetch('https://api.linkedin.com/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    const linkedinUser = await userResponse.json();

    if (!linkedinUser.email) {
      return res.status(401).json({ detail: 'Could not retrieve email from LinkedIn' });
    }

    const sessionData = {
      id: linkedinUser.sub,
      email: linkedinUser.email,
      name: linkedinUser.name,
      picture: linkedinUser.picture,
      exp: Date.now() + (7 * 24 * 60 * 60 * 1000),
    };

    const accessToken = Buffer.from(JSON.stringify(sessionData)).toString('base64');

    const user = {
      id: 1,
      email: linkedinUser.email,
      first_name: linkedinUser.given_name || linkedinUser.name?.split(' ')[0] || '',
      last_name: linkedinUser.family_name || linkedinUser.name?.split(' ').slice(1).join(' ') || '',
      role: 'admin',
      is_active: true,
      email_verified: true,
      last_login: new Date().toISOString(),
      created_at: new Date().toISOString(),
    };

    return res.status(200).json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 604800,
      user,
    });
  } catch (error) {
    console.error('LinkedIn auth error:', error);
    return res.status(401).json({ detail: 'LinkedIn authentication failed' });
  }
}

// Get current user from token
async function handleMe(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ detail: 'Not authenticated' });
  }

  const token = authHeader.substring(7);

  try {
    const sessionData = JSON.parse(Buffer.from(token, 'base64').toString());

    if (sessionData.exp < Date.now()) {
      return res.status(401).json({ detail: 'Session expired' });
    }

    return res.status(200).json({
      id: 1,
      email: sessionData.email,
      first_name: sessionData.name?.split(' ')[0] || '',
      last_name: sessionData.name?.split(' ').slice(1).join(' ') || '',
      role: 'admin',
      is_active: true,
      email_verified: true,
      last_login: new Date().toISOString(),
      created_at: sessionData.created_at || new Date().toISOString(),
    });
  } catch (error) {
    return res.status(401).json({ detail: 'Invalid token' });
  }
}
