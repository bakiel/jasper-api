/**
 * JASPER Admin Auth - Get OAuth Client IDs
 * Returns Google and LinkedIn OAuth configuration
 * Combined to reduce serverless function count
 */

export default function handler(req, res) {
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

  // Check for provider query param for LinkedIn-specific request
  const { provider } = req.query;

  if (provider === 'linkedin') {
    const linkedinClientId = process.env.LINKEDIN_CLIENT_ID;
    const redirectUri = process.env.LINKEDIN_REDIRECT_URI || 'https://portal.jasperfinance.org/login';

    if (!linkedinClientId) {
      return res.status(503).json({ detail: 'LinkedIn OAuth not configured' });
    }

    return res.status(200).json({
      client_id: linkedinClientId,
      redirect_uri: redirectUri,
      scope: 'openid profile email'
    });
  }

  // Default: Google client ID
  const clientId = process.env.GOOGLE_CLIENT_ID;

  if (!clientId) {
    return res.status(503).json({ detail: 'Google OAuth not configured' });
  }

  return res.status(200).json({ client_id: clientId });
}
