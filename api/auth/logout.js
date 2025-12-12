// Logout endpoint
// Clears session cookie and redirects to home

export default function handler(req, res) {
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
