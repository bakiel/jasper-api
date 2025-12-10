/**
 * JASPER Admin Auth - Get Current User
 * Verifies JWT token and returns user data
 */
import { jwtVerify } from 'jose';

const SECRET_KEY = process.env.SECRET_KEY;

function getSecretKey() {
  return new TextEncoder().encode(SECRET_KEY);
}

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

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

    if (!SECRET_KEY) {
      return res.status(503).json({ detail: 'Auth not configured' });
    }

    // Verify JWT
    const { payload } = await jwtVerify(token, getSecretKey());

    if (payload.type !== 'admin') {
      return res.status(401).json({ detail: 'Invalid token type' });
    }

    // Return user data from token
    return res.status(200).json({
      id: payload.admin_id,
      email: payload.email,
      first_name: payload.email?.split('@')[0] || 'User',
      last_name: '',
      role: payload.role,
      is_active: true,
      email_verified: true,
      last_login: new Date().toISOString(),
      created_at: new Date().toISOString()
    });

  } catch (error) {
    if (error.code === 'ERR_JWT_EXPIRED') {
      return res.status(401).json({ detail: 'Token expired' });
    }
    console.error('Auth error:', error);
    return res.status(401).json({ detail: 'Invalid token' });
  }
}
