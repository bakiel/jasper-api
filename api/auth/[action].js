// Consolidated auth endpoint - handles all public auth routes
export default async function handler(req, res) {
  const { action } = req.query;

  switch (action) {
    case 'google':
      return handleGoogleInit(req, res);
    case 'callback':
      return handleCallback(req, res);
    case 'me':
      return handleMe(req, res);
    case 'logout':
      return handleLogout(req, res);
    default:
      return res.status(404).json({ error: 'Not found' });
  }
}

// Initiate Google OAuth
function handleGoogleInit(req, res) {
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

// Handle OAuth callback
async function handleCallback(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { code, state, error: oauthError } = req.query;
  const frontendUrl = 'https://jasperfinance.org';

  if (oauthError) {
    return res.redirect(302, `${frontendUrl}/login?error=oauth_denied`);
  }

  if (!code) {
    return res.redirect(302, `${frontendUrl}/login?error=no_code`);
  }

  // Verify state
  const cookies = parseCookies(req.headers.cookie || '');
  if (!cookies.oauth_state || cookies.oauth_state !== state) {
    return res.redirect(302, `${frontendUrl}/login?error=invalid_state`);
  }

  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: 'https://api.jasperfinance.org/auth/callback',
        grant_type: 'authorization_code',
      }),
    });

    const tokens = await tokenResponse.json();
    if (tokens.error) {
      return res.redirect(302, `${frontendUrl}/login?error=token_exchange`);
    }

    const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    const user = await userResponse.json();

    if (!user.email) {
      return res.redirect(302, `${frontendUrl}/login?error=no_email`);
    }

    const sessionData = {
      id: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture,
      exp: Date.now() + (7 * 24 * 60 * 60 * 1000),
    };

    const sessionToken = Buffer.from(JSON.stringify(sessionData)).toString('base64');

    res.setHeader('Set-Cookie', [
      'oauth_state=; Path=/; HttpOnly; Max-Age=0',
      `jasper_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800; Secure; Domain=.jasperfinance.org`,
    ]);

    res.redirect(302, `${frontendUrl}/portal`);
  } catch (error) {
    console.error('Auth callback error:', error);
    return res.redirect(302, `${frontendUrl}/login?error=server_error`);
  }
}

// Get current user session
function handleMe(req, res) {
  res.setHeader('Access-Control-Allow-Origin', 'https://jasperfinance.org');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const cookies = parseCookies(req.headers.cookie || '');
  const sessionToken = cookies.jasper_session;

  if (!sessionToken) {
    return res.status(401).json({ authenticated: false, error: 'Not authenticated' });
  }

  try {
    const sessionData = JSON.parse(Buffer.from(sessionToken, 'base64').toString());

    if (sessionData.exp < Date.now()) {
      return res.status(401).json({ authenticated: false, error: 'Session expired' });
    }

    return res.status(200).json({
      authenticated: true,
      user: {
        id: sessionData.id,
        email: sessionData.email,
        name: sessionData.name,
        picture: sessionData.picture,
      }
    });
  } catch (error) {
    return res.status(401).json({ authenticated: false, error: 'Invalid session' });
  }
}

// Logout
function handleLogout(req, res) {
  res.setHeader('Set-Cookie', 'jasper_session=; Path=/; HttpOnly; Max-Age=0; Secure; Domain=.jasperfinance.org');

  if (req.headers.accept?.includes('application/json')) {
    return res.status(200).json({ success: true, message: 'Logged out' });
  }

  res.redirect(302, 'https://jasperfinance.org/login?logged_out=true');
}

// Helper
function parseCookies(cookieString) {
  const cookies = {};
  if (!cookieString) return cookies;
  cookieString.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.trim().split('=');
    if (name) cookies[name] = rest.join('=');
  });
  return cookies;
}
