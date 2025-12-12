/**
 * JASPER Admin Auth - OAuth Login (Google & LinkedIn)
 * Verifies OAuth tokens and returns JWT
 * Combined to reduce serverless function count
 *
 * For Google: POST with { credential: "ID_TOKEN" }
 * For LinkedIn: POST with { provider: "linkedin", code: "AUTH_CODE", redirect_uri: "URI" }
 */
import { SignJWT } from 'jose';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const LINKEDIN_CLIENT_ID = process.env.LINKEDIN_CLIENT_ID;
const LINKEDIN_CLIENT_SECRET = process.env.LINKEDIN_CLIENT_SECRET;
const LINKEDIN_REDIRECT_URI = process.env.LINKEDIN_REDIRECT_URI || 'https://portal.jasperfinance.org/login';
const SECRET_KEY = process.env.SECRET_KEY;

// Encode the secret key for jose
function getSecretKey() {
  return new TextEncoder().encode(SECRET_KEY);
}

// Create JWT token for admin user
async function createAdminToken(user, provider = 'google') {
  const expiresIn = 8 * 60 * 60; // 8 hours in seconds

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
    .setJti(crypto.randomUUID())
    .sign(getSecretKey());

  return { token, expiresIn };
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

// Handle Google OAuth
async function handleGoogleAuth(credential, res) {
  if (!GOOGLE_CLIENT_ID || !SECRET_KEY) {
    return res.status(503).json({ detail: 'Google OAuth not configured' });
  }

  // Verify Google ID token with Google's tokeninfo endpoint
  const googleResponse = await fetch(
    `https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`
  );

  if (!googleResponse.ok) {
    return res.status(401).json({ detail: 'Invalid Google token' });
  }

  const googleData = await googleResponse.json();

  // Verify the token is for our app
  if (googleData.aud !== GOOGLE_CLIENT_ID) {
    return res.status(401).json({ detail: 'Token not intended for this application' });
  }

  const email = (googleData.email || '').toLowerCase();
  const emailVerified = googleData.email_verified === true || googleData.email_verified === 'true';
  const givenName = googleData.given_name || '';
  const familyName = googleData.family_name || '';

  if (!email || !emailVerified) {
    return res.status(401).json({ detail: 'Email not verified with Google' });
  }

  const user = {
    id: hashCode(email),
    email: email,
    first_name: givenName || 'Google',
    last_name: familyName || 'User',
    role: 'admin',
    is_active: true,
    email_verified: true,
    last_login: new Date().toISOString(),
    created_at: new Date().toISOString(),
    auth_provider: 'google'
  };

  const { token, expiresIn } = await createAdminToken(user, 'google');

  return res.status(200).json({
    access_token: token,
    token_type: 'bearer',
    expires_in: expiresIn,
    user: user
  });
}

// Handle LinkedIn OAuth
async function handleLinkedInAuth(code, redirectUri, res) {
  if (!LINKEDIN_CLIENT_ID || !LINKEDIN_CLIENT_SECRET || !SECRET_KEY) {
    return res.status(503).json({ detail: 'LinkedIn OAuth not configured' });
  }

  const actualRedirectUri = redirectUri || LINKEDIN_REDIRECT_URI;

  // Exchange authorization code for access token
  const tokenResponse = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: code,
      client_id: LINKEDIN_CLIENT_ID,
      client_secret: LINKEDIN_CLIENT_SECRET,
      redirect_uri: actualRedirectUri,
    }),
  });

  if (!tokenResponse.ok) {
    const errorData = await tokenResponse.text();
    console.error('LinkedIn token exchange failed:', errorData);
    console.error('Request params - code:', code?.substring(0, 20) + '...', 'redirect_uri:', actualRedirectUri);
    return res.status(401).json({ detail: 'Failed to exchange authorization code', error: errorData });
  }

  const tokenData = await tokenResponse.json();
  const accessToken = tokenData.access_token;

  if (!accessToken) {
    return res.status(401).json({ detail: 'No access token received from LinkedIn' });
  }

  // Get user profile using OpenID Connect userinfo endpoint
  const userInfoResponse = await fetch('https://api.linkedin.com/v2/userinfo', {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  });

  if (!userInfoResponse.ok) {
    const errorData = await userInfoResponse.text();
    console.error('LinkedIn userinfo failed:', userInfoResponse.status, errorData);
    return res.status(401).json({
      detail: 'Failed to fetch LinkedIn user info',
      error: errorData,
      status: userInfoResponse.status
    });
  }

  const userInfo = await userInfoResponse.json();

  const email = (userInfo.email || '').toLowerCase();
  const emailVerified = userInfo.email_verified === true;
  const givenName = userInfo.given_name || '';
  const familyName = userInfo.family_name || '';
  const picture = userInfo.picture || '';
  const linkedinSub = userInfo.sub || '';

  if (!email) {
    return res.status(401).json({ detail: 'No email address provided by LinkedIn' });
  }

  if (!emailVerified) {
    return res.status(401).json({ detail: 'LinkedIn email not verified' });
  }

  const user = {
    id: hashCode(email),
    email: email,
    first_name: givenName || 'LinkedIn',
    last_name: familyName || 'User',
    role: 'admin',
    is_active: true,
    email_verified: true,
    picture: picture,
    linkedin_sub: linkedinSub,
    last_login: new Date().toISOString(),
    created_at: new Date().toISOString(),
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
    const { provider, credential, code, redirect_uri } = req.body;

    // LinkedIn OAuth
    if (provider === 'linkedin' || code) {
      if (!code) {
        return res.status(400).json({ detail: 'Authorization code required for LinkedIn' });
      }
      return await handleLinkedInAuth(code, redirect_uri, res);
    }

    // Google OAuth (default)
    if (!credential) {
      return res.status(400).json({ detail: 'Google credential required' });
    }
    return await handleGoogleAuth(credential, res);

  } catch (error) {
    console.error('OAuth auth error:', error);
    return res.status(500).json({ detail: 'Authentication failed' });
  }
}
