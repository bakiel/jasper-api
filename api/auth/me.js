// Get current user session
export default function handler(req, res) {
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

function parseCookies(cookieString) {
  const cookies = {};
  if (!cookieString) return cookies;
  cookieString.split(';').forEach(cookie => {
    const [name, ...rest] = cookie.trim().split('=');
    if (name) cookies[name] = rest.join('=');
  });
  return cookies;
}
