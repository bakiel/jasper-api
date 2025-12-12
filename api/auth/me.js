// Get current user session
// Returns user info if authenticated, 401 if not

export default function handler(req, res) {
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
