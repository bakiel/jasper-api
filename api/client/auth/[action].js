// Client Portal auth endpoint - handles all client auth routes
import { OAuth2Client } from 'google-auth-library';
import { sql } from '../../lib/db.js';
import {
  hashPassword,
  verifyPassword,
  generateVerificationCode,
  generateToken,
  hashToken,
  createAccessToken,
  createRefreshToken,
  verifyToken,
  validatePassword,
  validateEmail,
  checkRateLimit,
  clearRateLimit
} from '../../lib/auth.js';
import {
  sendVerificationEmail,
  sendPasswordResetEmail,
  sendWelcomeEmail,
  sendAdminNotification
} from '../../lib/email.js';

const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  const { action } = req.query;

  // Route to appropriate handler
  switch (action) {
    case 'register':
      return handleRegister(req, res);
    case 'verify-email':
      return handleVerifyEmail(req, res);
    case 'resend-code':
      return handleResendCode(req, res);
    case 'login':
      return handleLogin(req, res);
    case 'forgot-password':
      return handleForgotPassword(req, res);
    case 'reset-password':
      return handleResetPassword(req, res);
    case 'refresh':
      return handleRefreshToken(req, res);
    case 'google':
      return handleGoogle(req, res);
    case 'google-client-id':
      return handleGoogleClientId(req, res);
    case 'linkedin':
      return handleLinkedIn(req, res);
    case 'linkedin-client-id':
      return handleLinkedInClientId(req, res);
    case 'me':
      return handleMe(req, res);
    case 'logout':
      return handleLogout(req, res);
    default:
      return res.status(404).json({ error: 'Not found' });
  }
}

// ============================================
// EMAIL/PASSWORD AUTHENTICATION
// ============================================

// Register new client
async function handleRegister(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, password, full_name, company_name } = req.body;

    // Validate required fields
    if (!email || !password || !full_name) {
      return res.status(400).json({
        detail: 'Email, password, and full name are required'
      });
    }

    // Validate email format
    if (!validateEmail(email)) {
      return res.status(400).json({ detail: 'Invalid email format' });
    }

    // Validate password strength
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        detail: 'Password does not meet requirements',
        errors: passwordValidation.errors
      });
    }

    // Check rate limit
    const rateLimit = checkRateLimit(`register:${email}`, 3, 60 * 60 * 1000); // 3 attempts per hour
    if (!rateLimit.allowed) {
      return res.status(429).json({
        detail: 'Too many registration attempts. Please try again later.',
        retry_after: rateLimit.retryAfter
      });
    }

    // Check if email already exists
    const existingUser = await sql`
      SELECT id, email_verified, status FROM client_users WHERE email = ${email.toLowerCase()}
    `;

    if (existingUser.length > 0) {
      const user = existingUser[0];
      if (user.email_verified) {
        return res.status(400).json({ detail: 'Email already registered' });
      } else {
        // User exists but not verified - allow re-registration
        await sql`DELETE FROM client_users WHERE id = ${user.id}`;
      }
    }

    // Hash password
    const passwordHash = hashPassword(password);

    // Generate verification code
    const verificationCode = generateVerificationCode();
    const verificationExpires = new Date(Date.now() + 15 * 60 * 1000); // 15 minutes

    // Create user
    const newUser = await sql`
      INSERT INTO client_users (
        email, password_hash, full_name, company_name,
        email_verification_code, email_verification_expires,
        status
      )
      VALUES (
        ${email.toLowerCase()}, ${passwordHash}, ${full_name}, ${company_name || null},
        ${verificationCode}, ${verificationExpires},
        'pending_verification'
      )
      RETURNING id, email, full_name, company_name, status, created_at
    `;

    // Send verification email
    const emailResult = await sendVerificationEmail(email, full_name, verificationCode);

    if (!emailResult.success) {
      console.error('Failed to send verification email:', emailResult.error);
      // Don't fail registration, but log the error
    }

    return res.status(201).json({
      message: 'Registration successful. Please check your email for the verification code.',
      user: {
        id: newUser[0].id,
        email: newUser[0].email,
        full_name: newUser[0].full_name,
        status: newUser[0].status
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ detail: 'Registration failed. Please try again.' });
  }
}

// Verify email with code
async function handleVerifyEmail(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, code } = req.body;

    if (!email || !code) {
      return res.status(400).json({ detail: 'Email and verification code are required' });
    }

    // Check rate limit
    const rateLimit = checkRateLimit(`verify:${email}`, 5, 15 * 60 * 1000); // 5 attempts per 15 min
    if (!rateLimit.allowed) {
      return res.status(429).json({
        detail: 'Too many verification attempts. Please try again later.',
        retry_after: rateLimit.retryAfter
      });
    }

    // Find user
    const users = await sql`
      SELECT id, full_name, email_verification_code, email_verification_expires, status
      FROM client_users
      WHERE email = ${email.toLowerCase()}
    `;

    if (users.length === 0) {
      return res.status(404).json({ detail: 'User not found' });
    }

    const user = users[0];

    if (user.status !== 'pending_verification') {
      return res.status(400).json({ detail: 'Email already verified' });
    }

    // Check if code has expired
    if (new Date() > new Date(user.email_verification_expires)) {
      return res.status(400).json({ detail: 'Verification code has expired. Please request a new one.' });
    }

    // Check if code matches
    if (user.email_verification_code !== code) {
      return res.status(400).json({ detail: 'Invalid verification code' });
    }

    // Update user status
    await sql`
      UPDATE client_users
      SET
        email_verified = TRUE,
        email_verification_code = NULL,
        email_verification_expires = NULL,
        status = 'pending_approval',
        updated_at = NOW()
      WHERE id = ${user.id}
    `;

    // Create onboarding record
    await sql`
      INSERT INTO client_onboarding (user_id)
      VALUES (${user.id})
      ON CONFLICT (user_id) DO NOTHING
    `;

    // Create preferences record
    await sql`
      INSERT INTO client_user_preferences (user_id)
      VALUES (${user.id})
      ON CONFLICT (user_id) DO NOTHING
    `;

    // Notify admin of new registration
    const userDetails = await sql`SELECT full_name, email, company_name FROM client_users WHERE id = ${user.id}`;
    await sendAdminNotification(
      userDetails[0].full_name,
      userDetails[0].email,
      userDetails[0].company_name
    );

    // Clear rate limit
    clearRateLimit(`verify:${email}`);

    return res.status(200).json({
      message: 'Email verified successfully. Your account is pending approval.',
      status: 'pending_approval'
    });
  } catch (error) {
    console.error('Verification error:', error);
    return res.status(500).json({ detail: 'Verification failed. Please try again.' });
  }
}

// Resend verification code
async function handleResendCode(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ detail: 'Email is required' });
    }

    // Check rate limit (1 per minute)
    const rateLimit = checkRateLimit(`resend:${email}`, 1, 60 * 1000);
    if (!rateLimit.allowed) {
      return res.status(429).json({
        detail: 'Please wait before requesting another code.',
        retry_after: rateLimit.retryAfter
      });
    }

    // Find user
    const users = await sql`
      SELECT id, full_name, status FROM client_users WHERE email = ${email.toLowerCase()}
    `;

    if (users.length === 0) {
      // Don't reveal if email exists
      return res.status(200).json({ message: 'If an account exists, a new code has been sent.' });
    }

    const user = users[0];

    if (user.status !== 'pending_verification') {
      return res.status(200).json({ message: 'If an account exists, a new code has been sent.' });
    }

    // Generate new code
    const verificationCode = generateVerificationCode();
    const verificationExpires = new Date(Date.now() + 15 * 60 * 1000);

    // Update user
    await sql`
      UPDATE client_users
      SET
        email_verification_code = ${verificationCode},
        email_verification_expires = ${verificationExpires},
        updated_at = NOW()
      WHERE id = ${user.id}
    `;

    // Send email
    await sendVerificationEmail(email, user.full_name, verificationCode);

    return res.status(200).json({ message: 'A new verification code has been sent to your email.' });
  } catch (error) {
    console.error('Resend code error:', error);
    return res.status(500).json({ detail: 'Failed to resend code. Please try again.' });
  }
}

// Login with email/password
async function handleLogin(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ detail: 'Email and password are required' });
    }

    // Check rate limit
    const rateLimit = checkRateLimit(`login:${email}`, 5, 15 * 60 * 1000);
    if (!rateLimit.allowed) {
      return res.status(429).json({
        detail: 'Too many login attempts. Please try again later.',
        retry_after: rateLimit.retryAfter
      });
    }

    // Find user
    const users = await sql`
      SELECT id, email, password_hash, full_name, company_name, avatar_url,
             status, email_verified, locked_until, failed_login_attempts
      FROM client_users
      WHERE email = ${email.toLowerCase()}
    `;

    if (users.length === 0) {
      return res.status(401).json({ detail: 'Invalid email or password' });
    }

    const user = users[0];

    // Check if account is locked
    if (user.locked_until && new Date() < new Date(user.locked_until)) {
      const minutesLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
      return res.status(423).json({
        detail: `Account is locked. Please try again in ${minutesLeft} minutes.`
      });
    }

    // Check password (only for email/password accounts)
    if (!user.password_hash) {
      return res.status(400).json({
        detail: 'This account uses social login. Please sign in with Google or LinkedIn.'
      });
    }

    const passwordValid = verifyPassword(password, user.password_hash);

    if (!passwordValid) {
      // Increment failed attempts
      const failedAttempts = (user.failed_login_attempts || 0) + 1;
      let lockUntil = null;

      if (failedAttempts >= 5) {
        lockUntil = new Date(Date.now() + 15 * 60 * 1000); // Lock for 15 minutes
      }

      await sql`
        UPDATE client_users
        SET failed_login_attempts = ${failedAttempts}, locked_until = ${lockUntil}
        WHERE id = ${user.id}
      `;

      if (lockUntil) {
        return res.status(423).json({
          detail: 'Too many failed attempts. Account locked for 15 minutes.'
        });
      }

      return res.status(401).json({ detail: 'Invalid email or password' });
    }

    // Check email verification
    if (!user.email_verified) {
      return res.status(403).json({
        detail: 'Please verify your email before logging in.',
        code: 'EMAIL_NOT_VERIFIED'
      });
    }

    // Check account status
    if (user.status === 'pending_approval') {
      return res.status(403).json({
        detail: 'Your account is pending approval. You will receive an email once approved.',
        code: 'PENDING_APPROVAL'
      });
    }

    if (user.status === 'suspended') {
      return res.status(403).json({
        detail: 'Your account has been suspended. Please contact support.',
        code: 'ACCOUNT_SUSPENDED'
      });
    }

    if (user.status !== 'active') {
      return res.status(403).json({
        detail: 'Account is not active. Please contact support.',
        code: 'ACCOUNT_INACTIVE'
      });
    }

    // Clear failed attempts and rate limit
    await sql`
      UPDATE client_users
      SET failed_login_attempts = 0, locked_until = NULL, last_login_at = NOW(), login_count = login_count + 1
      WHERE id = ${user.id}
    `;
    clearRateLimit(`login:${email}`);

    // Check onboarding status
    const onboarding = await sql`
      SELECT completed FROM client_onboarding WHERE user_id = ${user.id}
    `;
    const onboardingCompleted = onboarding.length > 0 ? onboarding[0].completed : false;

    // Create tokens
    const tokenPayload = {
      sub: user.id,
      email: user.email,
      role: 'client',
      type: 'access'
    };

    const accessToken = await createAccessToken(tokenPayload, '15m');
    const refreshToken = await createRefreshToken({ ...tokenPayload, type: 'refresh' });

    // Store session
    await sql`
      INSERT INTO client_sessions (user_id, token_hash, refresh_token_hash, expires_at, refresh_expires_at)
      VALUES (
        ${user.id},
        ${hashToken(accessToken)},
        ${hashToken(refreshToken)},
        ${new Date(Date.now() + 15 * 60 * 1000)},
        ${new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)}
      )
    `;

    return res.status(200).json({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      user: {
        id: user.id,
        email: user.email,
        name: user.full_name,
        company: user.company_name,
        avatar_url: user.avatar_url,
        onboarding_completed: onboardingCompleted
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ detail: 'Login failed. Please try again.' });
  }
}

// Forgot password
async function handleForgotPassword(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ detail: 'Email is required' });
    }

    // Rate limit
    const rateLimit = checkRateLimit(`forgot:${email}`, 3, 60 * 60 * 1000); // 3 per hour
    if (!rateLimit.allowed) {
      return res.status(429).json({
        detail: 'Too many password reset requests. Please try again later.',
        retry_after: rateLimit.retryAfter
      });
    }

    // Always return success (don't reveal if email exists)
    const successMessage = 'If an account with that email exists, a password reset link has been sent.';

    // Find user
    const users = await sql`
      SELECT id, full_name, password_hash FROM client_users WHERE email = ${email.toLowerCase()}
    `;

    if (users.length === 0 || !users[0].password_hash) {
      // User doesn't exist or is OAuth-only
      return res.status(200).json({ message: successMessage });
    }

    const user = users[0];

    // Generate reset token
    const resetToken = generateToken();
    const resetExpires = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

    // Save token
    await sql`
      UPDATE client_users
      SET password_reset_token = ${hashToken(resetToken)}, password_reset_expires = ${resetExpires}
      WHERE id = ${user.id}
    `;

    // Send email
    await sendPasswordResetEmail(email, user.full_name, resetToken);

    return res.status(200).json({ message: successMessage });
  } catch (error) {
    console.error('Forgot password error:', error);
    return res.status(500).json({ detail: 'Request failed. Please try again.' });
  }
}

// Reset password
async function handleResetPassword(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ detail: 'Token and new password are required' });
    }

    // Validate password
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.valid) {
      return res.status(400).json({
        detail: 'Password does not meet requirements',
        errors: passwordValidation.errors
      });
    }

    const tokenHash = hashToken(token);

    // Find user with valid reset token
    const users = await sql`
      SELECT id, password_reset_expires
      FROM client_users
      WHERE password_reset_token = ${tokenHash}
    `;

    if (users.length === 0) {
      return res.status(400).json({ detail: 'Invalid or expired reset token' });
    }

    const user = users[0];

    // Check if token has expired
    if (new Date() > new Date(user.password_reset_expires)) {
      return res.status(400).json({ detail: 'Reset token has expired. Please request a new one.' });
    }

    // Hash new password
    const passwordHash = hashPassword(password);

    // Update password and clear reset token
    await sql`
      UPDATE client_users
      SET
        password_hash = ${passwordHash},
        password_reset_token = NULL,
        password_reset_expires = NULL,
        failed_login_attempts = 0,
        locked_until = NULL,
        updated_at = NOW()
      WHERE id = ${user.id}
    `;

    // Invalidate all sessions
    await sql`DELETE FROM client_sessions WHERE user_id = ${user.id}`;

    return res.status(200).json({ message: 'Password reset successfully. You can now log in with your new password.' });
  } catch (error) {
    console.error('Reset password error:', error);
    return res.status(500).json({ detail: 'Password reset failed. Please try again.' });
  }
}

// Refresh token
async function handleRefreshToken(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({ detail: 'Refresh token is required' });
    }

    // Verify token
    const payload = await verifyToken(refresh_token);

    if (!payload || payload.type !== 'refresh') {
      return res.status(401).json({ detail: 'Invalid refresh token' });
    }

    // Check if session exists
    const sessions = await sql`
      SELECT id FROM client_sessions
      WHERE user_id = ${payload.sub} AND refresh_token_hash = ${hashToken(refresh_token)}
    `;

    if (sessions.length === 0) {
      return res.status(401).json({ detail: 'Session not found' });
    }

    // Get user
    const users = await sql`
      SELECT id, email, full_name, company_name, avatar_url, status
      FROM client_users WHERE id = ${payload.sub}
    `;

    if (users.length === 0 || users[0].status !== 'active') {
      return res.status(401).json({ detail: 'User not found or inactive' });
    }

    const user = users[0];

    // Create new access token
    const newPayload = {
      sub: user.id,
      email: user.email,
      role: 'client',
      type: 'access'
    };

    const accessToken = await createAccessToken(newPayload, '15m');

    // Update session
    await sql`
      UPDATE client_sessions
      SET token_hash = ${hashToken(accessToken)}, expires_at = ${new Date(Date.now() + 15 * 60 * 1000)}
      WHERE id = ${sessions[0].id}
    `;

    return res.status(200).json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900
    });
  } catch (error) {
    console.error('Refresh token error:', error);
    return res.status(500).json({ detail: 'Token refresh failed' });
  }
}

// ============================================
// OAUTH AUTHENTICATION (existing)
// ============================================

// Google OAuth client ID
async function handleGoogleClientId(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) {
    return res.status(500).json({ error: 'Google OAuth not configured' });
  }
  return res.status(200).json({ client_id: clientId });
}

// Google OAuth login for clients
async function handleGoogle(req, res) {
  if (req.method === 'GET') {
    return handleGoogleClientId(req, res);
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ detail: 'Credential required' });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: credential,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const { sub: googleId, email, name, picture } = payload;

    // Check if user exists
    let users = await sql`
      SELECT id, email, full_name, company_name, avatar_url, status, email_verified
      FROM client_users WHERE google_id = ${googleId} OR email = ${email.toLowerCase()}
    `;

    let user;
    let isNewUser = false;

    if (users.length === 0) {
      // Create new user (auto-verified via Google)
      const newUsers = await sql`
        INSERT INTO client_users (
          email, full_name, google_id, avatar_url,
          email_verified, status
        )
        VALUES (${email.toLowerCase()}, ${name}, ${googleId}, ${picture}, TRUE, 'pending_approval')
        RETURNING id, email, full_name, company_name, avatar_url, status
      `;
      user = newUsers[0];
      isNewUser = true;

      // Create onboarding and preferences records
      await sql`INSERT INTO client_onboarding (user_id) VALUES (${user.id})`;
      await sql`INSERT INTO client_user_preferences (user_id) VALUES (${user.id})`;

      // Notify admin (fire-and-forget, don't block response)
      sendAdminNotification(name, email, null).catch(err => console.error('Admin notification failed:', err.message));
    } else {
      user = users[0];

      // Link Google account if not linked
      if (!users[0].google_id) {
        await sql`
          UPDATE client_users
          SET google_id = ${googleId}, email_verified = TRUE, updated_at = NOW()
          WHERE id = ${user.id}
        `;
      }

      // Update avatar if not set
      if (!user.avatar_url && picture) {
        await sql`UPDATE client_users SET avatar_url = ${picture} WHERE id = ${user.id}`;
        user.avatar_url = picture;
      }
    }

    // Check account status
    if (user.status === 'pending_approval') {
      return res.status(403).json({
        detail: 'Your account is pending approval. You will receive an email once approved.',
        code: 'PENDING_APPROVAL'
      });
    }

    if (user.status === 'suspended') {
      return res.status(403).json({
        detail: 'Your account has been suspended. Please contact support.',
        code: 'ACCOUNT_SUSPENDED'
      });
    }

    // For pending_verification, auto-approve since Google verified email
    if (user.status === 'pending_verification') {
      await sql`
        UPDATE client_users SET status = 'pending_approval', email_verified = TRUE WHERE id = ${user.id}
      `;
      return res.status(403).json({
        detail: 'Your account is pending approval. You will receive an email once approved.',
        code: 'PENDING_APPROVAL'
      });
    }

    // Update login stats
    await sql`
      UPDATE client_users
      SET last_login_at = NOW(), login_count = login_count + 1
      WHERE id = ${user.id}
    `;

    // Check onboarding
    const onboarding = await sql`SELECT completed FROM client_onboarding WHERE user_id = ${user.id}`;
    const onboardingCompleted = onboarding.length > 0 ? onboarding[0].completed : false;

    // Create tokens
    const tokenPayload = { sub: user.id, email: user.email, role: 'client', type: 'access' };
    const accessToken = await createAccessToken(tokenPayload, '15m');
    const refreshToken = await createRefreshToken({ ...tokenPayload, type: 'refresh' });

    // Store session
    await sql`
      INSERT INTO client_sessions (user_id, token_hash, refresh_token_hash, expires_at, refresh_expires_at)
      VALUES (${user.id}, ${hashToken(accessToken)}, ${hashToken(refreshToken)},
              ${new Date(Date.now() + 15 * 60 * 1000)}, ${new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)})
    `;

    return res.status(200).json({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 900,
      user: {
        id: user.id,
        email: user.email,
        name: user.full_name,
        company: user.company_name,
        avatar_url: user.avatar_url,
        onboarding_completed: onboardingCompleted
      }
    });
  } catch (error) {
    console.error('Client Google auth error:', error);
    return res.status(401).json({ detail: 'Invalid Google credential' });
  }
}

// LinkedIn OAuth client config
async function handleLinkedInClientId(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }
  const clientId = process.env.LINKEDIN_CLIENT_ID;
  if (!clientId) {
    return res.status(500).json({ error: 'LinkedIn OAuth not configured' });
  }
  return res.status(200).json({
    client_id: clientId,
    redirect_uri: 'https://client.jasperfinance.org/login',
    scope: 'openid profile email',
  });
}

// LinkedIn OAuth login for clients
async function handleLinkedIn(req, res) {
  if (req.method === 'GET') {
    return handleLinkedInClientId(req, res);
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { code, redirect_uri } = req.body;

    if (!code) {
      return res.status(400).json({ detail: 'Code required' });
    }

    const clientId = process.env.LINKEDIN_CLIENT_ID;
    const clientSecret = process.env.LINKEDIN_CLIENT_SECRET;

    if (!clientId || !clientSecret) {
      return res.status(500).json({ detail: 'LinkedIn OAuth not configured' });
    }

    // Exchange code for token
    const tokenResponse = await fetch('https://www.linkedin.com/oauth/v2/accessToken', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirect_uri || 'https://client.jasperfinance.org/login',
        client_id: clientId,
        client_secret: clientSecret,
      }),
    });

    const tokens = await tokenResponse.json();

    if (tokens.error) {
      console.error('LinkedIn token error:', tokens);
      return res.status(401).json({
        detail: 'LinkedIn authentication failed',
        error: tokens.error_description || tokens.error
      });
    }

    // Get user info
    const userResponse = await fetch('https://api.linkedin.com/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });

    const linkedinUser = await userResponse.json();

    if (!linkedinUser.email) {
      return res.status(401).json({ detail: 'Could not retrieve email from LinkedIn' });
    }

    const linkedinId = linkedinUser.sub;
    const email = linkedinUser.email;
    const name = linkedinUser.name || `${linkedinUser.given_name || ''} ${linkedinUser.family_name || ''}`.trim();
    const picture = linkedinUser.picture;

    // Check if user exists
    let users = await sql`
      SELECT id, email, full_name, company_name, avatar_url, status
      FROM client_users WHERE linkedin_id = ${linkedinId} OR email = ${email.toLowerCase()}
    `;

    let user;

    if (users.length === 0) {
      // Create new user
      const newUsers = await sql`
        INSERT INTO client_users (
          email, full_name, linkedin_id, avatar_url,
          email_verified, status
        )
        VALUES (${email.toLowerCase()}, ${name}, ${linkedinId}, ${picture}, TRUE, 'pending_approval')
        RETURNING id, email, full_name, company_name, avatar_url, status
      `;
      user = newUsers[0];

      await sql`INSERT INTO client_onboarding (user_id) VALUES (${user.id})`;
      await sql`INSERT INTO client_user_preferences (user_id) VALUES (${user.id})`;
      // Notify admin (fire-and-forget, don't block response)
      sendAdminNotification(name, email, null).catch(err => console.error('Admin notification failed:', err.message));
    } else {
      user = users[0];

      if (!users[0].linkedin_id) {
        await sql`UPDATE client_users SET linkedin_id = ${linkedinId}, email_verified = TRUE WHERE id = ${user.id}`;
      }

      if (!user.avatar_url && picture) {
        await sql`UPDATE client_users SET avatar_url = ${picture} WHERE id = ${user.id}`;
        user.avatar_url = picture;
      }
    }

    // Check account status (same as Google)
    if (user.status === 'pending_approval' || user.status === 'pending_verification') {
      if (user.status === 'pending_verification') {
        await sql`UPDATE client_users SET status = 'pending_approval', email_verified = TRUE WHERE id = ${user.id}`;
      }
      return res.status(403).json({
        detail: 'Your account is pending approval. You will receive an email once approved.',
        code: 'PENDING_APPROVAL'
      });
    }

    if (user.status === 'suspended') {
      return res.status(403).json({
        detail: 'Your account has been suspended. Please contact support.',
        code: 'ACCOUNT_SUSPENDED'
      });
    }

    // Update login stats
    await sql`UPDATE client_users SET last_login_at = NOW(), login_count = login_count + 1 WHERE id = ${user.id}`;

    // Check onboarding
    const onboarding = await sql`SELECT completed FROM client_onboarding WHERE user_id = ${user.id}`;
    const onboardingCompleted = onboarding.length > 0 ? onboarding[0].completed : false;

    // Create tokens
    const tokenPayload = { sub: user.id, email: user.email, role: 'client', type: 'access' };
    const accessToken = await createAccessToken(tokenPayload, '15m');
    const refreshToken = await createRefreshToken({ ...tokenPayload, type: 'refresh' });

    await sql`
      INSERT INTO client_sessions (user_id, token_hash, refresh_token_hash, expires_at, refresh_expires_at)
      VALUES (${user.id}, ${hashToken(accessToken)}, ${hashToken(refreshToken)},
              ${new Date(Date.now() + 15 * 60 * 1000)}, ${new Date(Date.now() + 7 * 24 * 60 * 60 * 1000)})
    `;

    return res.status(200).json({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 900,
      user: {
        id: user.id,
        email: user.email,
        name: user.full_name,
        company: user.company_name,
        avatar_url: user.avatar_url,
        onboarding_completed: onboardingCompleted
      }
    });
  } catch (error) {
    console.error('Client LinkedIn auth error:', error);
    return res.status(401).json({ detail: 'LinkedIn authentication failed' });
  }
}

// ============================================
// SESSION MANAGEMENT
// ============================================

// Get current client user from token
async function handleMe(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ detail: 'Not authenticated' });
  }

  const token = authHeader.substring(7);

  try {
    const payload = await verifyToken(token);

    if (!payload || payload.role !== 'client') {
      return res.status(401).json({ detail: 'Invalid token' });
    }

    // Get user
    const users = await sql`
      SELECT id, email, full_name, company_name, avatar_url, status, created_at
      FROM client_users WHERE id = ${payload.sub}
    `;

    if (users.length === 0) {
      return res.status(401).json({ detail: 'User not found' });
    }

    const user = users[0];

    // Check onboarding
    const onboarding = await sql`SELECT completed FROM client_onboarding WHERE user_id = ${user.id}`;
    const onboardingCompleted = onboarding.length > 0 ? onboarding[0].completed : false;

    return res.status(200).json({
      id: user.id,
      email: user.email,
      name: user.full_name,
      company: user.company_name,
      avatar_url: user.avatar_url,
      onboarding_completed: onboardingCompleted,
      created_at: user.created_at
    });
  } catch (error) {
    console.error('Get me error:', error);
    return res.status(401).json({ detail: 'Invalid token' });
  }
}

// Logout
async function handleLogout(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    try {
      const payload = await verifyToken(token);
      if (payload) {
        // Delete session
        await sql`DELETE FROM client_sessions WHERE token_hash = ${hashToken(token)}`;
      }
    } catch (error) {
      // Ignore token errors during logout
    }
  }

  return res.status(200).json({ success: true, message: 'Logged out successfully' });
}
