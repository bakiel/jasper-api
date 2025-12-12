// Consolidated auth endpoint
// Handles: /auth/google, /auth/callback, /auth/me, /auth/logout

export default async function handler(req, res) {
  // Parse the path from the URL to determine which action to take
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  // Route to appropriate handler
  if (path.endsWith('/google') || path === '/auth/google') {
    return handleGoogleAuth(req, res);
  } else if (path.endsWith('/callback') || path === '/auth/callback') {
    return handleCallback(req, res);
  } else if (path.endsWith('/me') || path === '/auth/me') {
    return handleMe(req, res);
  } else if (path.endsWith('/logout') || path === '/auth/logout') {
    return handleLogout(req, res);
  }

  return res.status(404).json({ error: 'Auth endpoint not found' });
}

// ============ Google OAuth Initiation ============
function handleGoogleAuth(req, res) {
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

// ============ OAuth Callback ============
async function handleCallback(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const { code, state, error: oauthError } = req.query;
  const frontendUrl = process.env.FRONTEND_URL || 'https://jasperfinance.org';

  // Handle OAuth errors
  if (oauthError) {
    console.error('OAuth error:', oauthError);
    return res.redirect(302, `${frontendUrl}/login?error=oauth_denied`);
  }

  if (!code) {
    return res.redirect(302, `${frontendUrl}/login?error=no_code`);
  }

  // Verify state (CSRF protection)
  const cookies = parseCookies(req.headers.cookie || '');
  const storedState = cookies.oauth_state;

  if (!storedState || storedState !== state) {
    console.error('State mismatch:', { storedState, state });
    return res.redirect(302, `${frontendUrl}/login?error=invalid_state`);
  }

  try {
    // Exchange code for tokens
    const clientId = process.env.GOOGLE_CLIENT_ID;
    const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
    const redirectUri = process.env.NODE_ENV === 'production'
      ? 'https://api.jasperfinance.org/auth/callback'
      : 'http://localhost:3001/auth/callback';

    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });

    const tokens = await tokenResponse.json();

    if (tokens.error) {
      console.error('Token exchange error:', tokens);
      return res.redirect(302, `${frontendUrl}/login?error=token_exchange`);
    }

    // Get user info
    const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    const user = await userResponse.json();

    if (!user.email) {
      return res.redirect(302, `${frontendUrl}/login?error=no_email`);
    }

    // Create session token
    const sessionData = {
      id: user.id,
      email: user.email,
      name: user.name,
      picture: user.picture,
      exp: Date.now() + (7 * 24 * 60 * 60 * 1000), // 7 days
    };

    const sessionToken = Buffer.from(JSON.stringify(sessionData)).toString('base64');

    // Set session cookie
    const cookieOptions = [
      `jasper_session=${sessionToken}`,
      'Path=/',
      'HttpOnly',
      'SameSite=Lax',
      'Max-Age=604800', // 7 days
    ];

    if (process.env.NODE_ENV === 'production') {
      cookieOptions.push('Secure');
      cookieOptions.push('Domain=.jasperfinance.org');
    }

    // Clear oauth state and set session
    res.setHeader('Set-Cookie', [
      'oauth_state=; Path=/; HttpOnly; Max-Age=0',
      cookieOptions.join('; '),
    ]);

    // Redirect to portal
    res.redirect(302, `${frontendUrl}/portal`);

  } catch (error) {
    console.error('Auth callback error:', error);
    return res.redirect(302, `${frontendUrl}/login?error=server_error`);
  }
}

// ============ Get Current User ============
function handleMe(req, res) {
  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', process.env.FRONTEND_URL || 'https://jasperfinance.org');
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
    return res.status(401).json({
      authenticated: false,
      error: 'Not authenticated'
    });
  }

  try {
    const sessionData = JSON.parse(Buffer.from(sessionToken, 'base64').toString());

    // Check if session expired
    if (sessionData.exp < Date.now()) {
      return res.status(401).json({
        authenticated: false,
        error: 'Session expired'
      });
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
    console.error('Session parse error:', error);
    return res.status(401).json({
      authenticated: false,
      error: 'Invalid session'
    });
  }
}

// ============ Logout ============
function handleLogout(req, res) {
  const frontendUrl = process.env.FRONTEND_URL || 'https://jasperfinance.org';

  // Clear session cookie
  const cookieOptions = [
    'jasper_session=',
    'Path=/',
    'HttpOnly',
    'Max-Age=0',
  ];

  if (process.env.NODE_ENV === 'production') {
    cookieOptions.push('Secure');
    cookieOptions.push('Domain=.jasperfinance.org');
  }

  res.setHeader('Set-Cookie', cookieOptions.join('; '));

  // For API calls (AJAX), return JSON
  if (req.headers.accept?.includes('application/json')) {
    return res.status(200).json({ success: true, message: 'Logged out' });
  }

  // For direct navigation, redirect
  res.redirect(302, `${frontendUrl}/login?logged_out=true`);
}

// ============ Utility Functions ============
function generateState() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let state = '';
  for (let i = 0; i < 32; i++) {
    state += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return state;
}

function parseCookies(cookieString) {
  const cookies = {};
  if (!cookieString) return cookies;

  cookieString.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.trim().split('=');
    if (name) {
      cookies[name] = rest.join('=');
    }
  });

  return cookies;
}
