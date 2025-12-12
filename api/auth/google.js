// Google OAuth initiation endpoint
// Redirects user to Google's OAuth consent screen

export default function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const redirectUri = process.env.NODE_ENV === 'production'
    ? 'https://api.jasperfinance.org/auth/callback'
    : 'http://localhost:3001/auth/callback';

  if (!clientId) {
    return res.status(500).json({ error: 'Google OAuth not configured' });
  }

  const scope = encodeURIComponent('openid email profile');
  const state = generateState();

  // Store state in cookie for CSRF protection
  res.setHeader('Set-Cookie', `oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600${process.env.NODE_ENV === 'production' ? '; Secure' : ''}`);

  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${clientId}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&response_type=code` +
    `&scope=${scope}` +
    `&state=${state}` +
    `&access_type=offline` +
    `&prompt=consent`;

  res.redirect(302, authUrl);
}

function generateState() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let state = '';
  for (let i = 0; i < 32; i++) {
    state += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return state;
}
