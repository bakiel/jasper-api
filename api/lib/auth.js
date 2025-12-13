// Authentication utilities
import { SignJWT, jwtVerify } from 'jose';
import crypto from 'crypto';

const JWT_SECRET = new TextEncoder().encode(
  process.env.JWT_SECRET || 'jasper-client-portal-secret-key-change-in-production'
);

// Hash password using crypto (no bcrypt dependency needed)
export function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

// Verify password
export function verifyPassword(password, storedHash) {
  const [salt, hash] = storedHash.split(':');
  const verifyHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return hash === verifyHash;
}

// Generate verification code (6 digits)
export function generateVerificationCode() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// Generate secure random token
export function generateToken(length = 32) {
  return crypto.randomBytes(length).toString('hex');
}

// Hash token for storage
export function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

// Create JWT access token
export async function createAccessToken(payload, expiresIn = '15m') {
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(expiresIn)
    .sign(JWT_SECRET);
  return token;
}

// Create JWT refresh token
export async function createRefreshToken(payload) {
  const token = await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(JWT_SECRET);
  return token;
}

// Verify JWT token
export async function verifyToken(token) {
  try {
    const { payload } = await jwtVerify(token, JWT_SECRET);
    return payload;
  } catch (error) {
    return null;
  }
}

// Password validation
export function validatePassword(password) {
  const errors = [];

  if (password.length < 8) {
    errors.push('Password must be at least 8 characters');
  }
  if (!/[A-Z]/.test(password)) {
    errors.push('Password must contain at least one uppercase letter');
  }
  if (!/[a-z]/.test(password)) {
    errors.push('Password must contain at least one lowercase letter');
  }
  if (!/[0-9]/.test(password)) {
    errors.push('Password must contain at least one number');
  }
  if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
    errors.push('Password must contain at least one special character');
  }

  return {
    valid: errors.length === 0,
    errors
  };
}

// Email validation
export function validateEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Rate limiting helper (simple in-memory, use Redis in production)
const rateLimitStore = new Map();

export function checkRateLimit(key, maxAttempts = 5, windowMs = 15 * 60 * 1000) {
  const now = Date.now();
  const record = rateLimitStore.get(key);

  if (!record) {
    rateLimitStore.set(key, { attempts: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: maxAttempts - 1 };
  }

  if (now > record.resetAt) {
    rateLimitStore.set(key, { attempts: 1, resetAt: now + windowMs });
    return { allowed: true, remaining: maxAttempts - 1 };
  }

  if (record.attempts >= maxAttempts) {
    return {
      allowed: false,
      remaining: 0,
      retryAfter: Math.ceil((record.resetAt - now) / 1000)
    };
  }

  record.attempts++;
  return { allowed: true, remaining: maxAttempts - record.attempts };
}

// Clear rate limit
export function clearRateLimit(key) {
  rateLimitStore.delete(key);
}
