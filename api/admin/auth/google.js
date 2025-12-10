/**
 * JASPER Admin Auth - Google OAuth Login
 * Verifies Google ID token and returns JWT
 */
import { SignJWT, jwtVerify } from 'jose';

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const SECRET_KEY = process.env.SECRET_KEY;

// Encode the secret key for jose
function getSecretKey() {
  return new TextEncoder().encode(SECRET_KEY);
}

// Create JWT token for admin user
async function createAdminToken(user) {
  const expiresIn = 8 * 60 * 60; // 8 hours in seconds

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
    .setJti(crypto.randomUUID())
    .sign(getSecretKey());

  return { token, expiresIn };
}

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ detail: 'Method not allowed' });
  }

  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ detail: 'Google credential required' });
    }

    if (!GOOGLE_CLIENT_ID || !SECRET_KEY) {
      return res.status(503).json({ detail: 'OAuth not configured' });
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
    const emailVerified = googleData.email_verified === 'true';
    const givenName = googleData.given_name || '';
    const familyName = googleData.family_name || '';

    if (!email || !emailVerified) {
      return res.status(401).json({ detail: 'Email not verified with Google' });
    }

    // Create admin user object (in production, this would come from database)
    // For now, we'll create a simple user based on Google data
    const user = {
      id: Math.abs(hashCode(email)), // Generate consistent ID from email
      email: email,
      first_name: givenName || 'Google',
      last_name: familyName || 'User',
      role: 'admin',
      is_active: true,
      email_verified: true,
      last_login: new Date().toISOString(),
      created_at: new Date().toISOString()
    };

    // Generate JWT
    const { token, expiresIn } = await createAdminToken(user);

    return res.status(200).json({
      access_token: token,
      token_type: 'bearer',
      expires_in: expiresIn,
      user: user
    });

  } catch (error) {
    console.error('Google auth error:', error);
    return res.status(500).json({ detail: 'Authentication failed' });
  }
}

// Simple hash function to generate consistent user ID from email
function hashCode(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash;
}
