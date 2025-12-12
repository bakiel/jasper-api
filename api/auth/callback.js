// Google OAuth callback endpoint
// Exchanges auth code for tokens and creates session

export default async function handler(req, res) {
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

    // Create session token (simple JWT-like token)
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
