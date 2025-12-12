// Google OAuth initiation endpoint
export default function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const clientId = process.env.GOOGLE_CLIENT_ID;
  const redirectUri = 'https://api.jasperfinance.org/auth/callback';

  if (!clientId) {
    return res.status(500).json({ error: 'Google OAuth not configured' });
  }

  const scope = encodeURIComponent('openid email profile');
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let state = '';
  for (let i = 0; i < 32; i++) {
    state += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  res.setHeader('Set-Cookie', `oauth_state=${state}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600; Secure`);

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
