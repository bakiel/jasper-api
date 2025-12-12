// Logout endpoint
export default function handler(req, res) {
  res.setHeader('Set-Cookie', 'jasper_session=; Path=/; HttpOnly; Max-Age=0; Secure; Domain=.jasperfinance.org');

  if (req.headers.accept?.includes('application/json')) {
    return res.status(200).json({ success: true, message: 'Logged out' });
  }

  res.redirect(302, 'https://jasperfinance.org/login?logged_out=true');
}
