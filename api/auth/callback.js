// Google OAuth callback endpoint
export default async function handler(req, res) {
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

function parseCookies(cookieString) {
  const cookies = {};
  if (!cookieString) return cookies;
  cookieString.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.trim().split('=');
    if (name) cookies[name] = rest.join('=');
  });
  return cookies;
}
