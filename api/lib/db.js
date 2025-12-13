// Database connection using standard PostgreSQL (pg)
// Works with both local PostgreSQL and cloud databases

import pg from 'pg';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const { Pool } = pg;

// Load environment variables before initializing database connection
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const rootDir = join(__dirname, '..', '..');
const envFile = process.env.NODE_ENV === 'production' ? '.env.production' : '.env.local';
dotenv.config({ path: join(rootDir, envFile) });

// Create database pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('localhost') ? false : { rejectUnauthorized: false }
});

// Create a tagged template literal function compatible with existing code
// Usage: sql`SELECT * FROM users WHERE id = ${userId}`
function sql(strings, ...values) {
  // Handle tagged template literal
  if (Array.isArray(strings) && strings.raw) {
    let text = strings[0];
    const params = [];

    for (let i = 0; i < values.length; i++) {
      params.push(values[i]);
      text += `$${i + 1}${strings[i + 1]}`;
    }

    return pool.query(text, params).then(result => result.rows);
  }

  // Handle direct query call: sql(text, params)
  return pool.query(strings, values[0] || []).then(result => result.rows);
}

export { sql };

// Helper to run raw SQL queries
export async function query(text, params = []) {
  try {
    const result = await pool.query(text, params);
    return result.rows;
  } catch (error) {
    console.error('Database query error:', error);
    throw error;
  }
}

// Initialize database tables
export async function initDatabase() {
  try {
    // Client users table
    await sql`
      CREATE TABLE IF NOT EXISTS client_users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        full_name VARCHAR(255) NOT NULL,
        company_name VARCHAR(255),
        phone VARCHAR(50),
        avatar_url TEXT,

        google_id VARCHAR(255) UNIQUE,
        linkedin_id VARCHAR(255) UNIQUE,

        email_verified BOOLEAN DEFAULT FALSE,
        email_verification_code VARCHAR(6),
        email_verification_expires TIMESTAMP,

        status VARCHAR(50) DEFAULT 'pending_verification',
        approved_by UUID,
        approved_at TIMESTAMP,

        password_reset_token VARCHAR(255),
        password_reset_expires TIMESTAMP,

        last_login_at TIMESTAMP,
        login_count INTEGER DEFAULT 0,
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP,

        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `;

    // Client companies table
    await sql`
      CREATE TABLE IF NOT EXISTS client_companies (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        industry VARCHAR(100),
        website VARCHAR(255),
        address TEXT,
        city VARCHAR(100),
        country VARCHAR(100),
        logo_url TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;

    // Link users to companies
    await sql`
      CREATE TABLE IF NOT EXISTS client_company_members (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES client_users(id) ON DELETE CASCADE,
        company_id UUID REFERENCES client_companies(id) ON DELETE CASCADE,
        role VARCHAR(50) DEFAULT 'member',
        created_at TIMESTAMP DEFAULT NOW(),
        UNIQUE(user_id, company_id)
      )
    `;

    // User preferences
    await sql`
      CREATE TABLE IF NOT EXISTS client_user_preferences (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES client_users(id) ON DELETE CASCADE UNIQUE,
        email_notifications BOOLEAN DEFAULT TRUE,
        email_project_updates BOOLEAN DEFAULT TRUE,
        email_messages BOOLEAN DEFAULT TRUE,
        email_invoices BOOLEAN DEFAULT TRUE,
        theme VARCHAR(20) DEFAULT 'dark',
        timezone VARCHAR(50) DEFAULT 'Africa/Johannesburg',
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `;

    // Onboarding progress
    await sql`
      CREATE TABLE IF NOT EXISTS client_onboarding (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES client_users(id) ON DELETE CASCADE UNIQUE,
        completed BOOLEAN DEFAULT FALSE,
        completed_at TIMESTAMP,
        step_welcome BOOLEAN DEFAULT FALSE,
        step_profile BOOLEAN DEFAULT FALSE,
        step_company BOOLEAN DEFAULT FALSE,
        step_tour BOOLEAN DEFAULT FALSE,
        step_preferences BOOLEAN DEFAULT FALSE,
        current_step INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT NOW(),
        updated_at TIMESTAMP DEFAULT NOW()
      )
    `;

    // Sessions table for token management
    await sql`
      CREATE TABLE IF NOT EXISTS client_sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES client_users(id) ON DELETE CASCADE,
        token_hash VARCHAR(255) NOT NULL,
        refresh_token_hash VARCHAR(255),
        expires_at TIMESTAMP NOT NULL,
        refresh_expires_at TIMESTAMP,
        ip_address INET,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT NOW()
      )
    `;

    // Create indexes
    await sql`CREATE INDEX IF NOT EXISTS idx_client_users_email ON client_users(email)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_client_users_status ON client_users(status)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_client_sessions_user ON client_sessions(user_id)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_client_sessions_token ON client_sessions(token_hash)`;

    console.log('Database tables initialized successfully');
    return true;
  } catch (error) {
    console.error('Database initialization error:', error);
    throw error;
  }
}
