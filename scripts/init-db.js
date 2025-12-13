/**
 * JASPER Database Initialization Script
 *
 * This script creates all the necessary tables for the JASPER platform:
 * - Admin users (for the admin portal)
 * - Client users (for the client portal)
 * - Projects, documents, messages, etc.
 *
 * Run with: node scripts/init-db.js
 */

import { neon } from '@neondatabase/serverless';

// Get database URL from environment
const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL environment variable is required');
  console.log('\nTo set up your database:');
  console.log('1. Create a free Neon database at https://neon.tech');
  console.log('2. Copy the connection string');
  console.log('3. Set it as DATABASE_URL in your environment or .env file');
  process.exit(1);
}

const sql = neon(DATABASE_URL);

async function initDatabase() {
  console.log('🚀 Initializing JASPER database...\n');

  try {
    // ============================================
    // ADMIN TABLES
    // ============================================
    console.log('📦 Creating admin tables...');

    // Admin users table
    await sql`
      CREATE TABLE IF NOT EXISTS admin_users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        full_name VARCHAR(255) NOT NULL,
        role VARCHAR(50) DEFAULT 'admin',
        avatar_url TEXT,
        google_id VARCHAR(255) UNIQUE,
        linkedin_id VARCHAR(255) UNIQUE,
        last_login TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ admin_users');

    // ============================================
    // CLIENT TABLES
    // ============================================
    console.log('📦 Creating client tables...');

    // Client users table
    await sql`
      CREATE TABLE IF NOT EXISTS client_users (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255),
        full_name VARCHAR(255) NOT NULL,
        company_name VARCHAR(255),
        avatar_url TEXT,
        phone VARCHAR(50),

        -- OAuth fields
        google_id VARCHAR(255) UNIQUE,
        linkedin_id VARCHAR(255) UNIQUE,

        -- Verification fields
        email_verified BOOLEAN DEFAULT FALSE,
        email_verification_code VARCHAR(6),
        email_verification_expires TIMESTAMP WITH TIME ZONE,

        -- Password reset fields
        password_reset_token VARCHAR(255),
        password_reset_expires TIMESTAMP WITH TIME ZONE,

        -- Account status: pending_verification, pending_approval, active, suspended
        status VARCHAR(50) DEFAULT 'pending_verification',

        -- Security
        failed_login_attempts INTEGER DEFAULT 0,
        locked_until TIMESTAMP WITH TIME ZONE,

        -- Onboarding
        onboarding_completed BOOLEAN DEFAULT FALSE,

        -- Timestamps
        last_login TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ client_users');

    // Client companies table
    await sql`
      CREATE TABLE IF NOT EXISTS client_companies (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(255) NOT NULL,
        registration_number VARCHAR(100),
        industry VARCHAR(100),
        website VARCHAR(255),
        address TEXT,
        city VARCHAR(100),
        country VARCHAR(100),
        created_by UUID REFERENCES client_users(id),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ client_companies');

    // Client company members (links users to companies)
    await sql`
      CREATE TABLE IF NOT EXISTS client_company_members (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        company_id UUID REFERENCES client_companies(id) ON DELETE CASCADE,
        user_id UUID REFERENCES client_users(id) ON DELETE CASCADE,
        role VARCHAR(50) DEFAULT 'member',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(company_id, user_id)
      )
    `;
    console.log('  ✓ client_company_members');

    // Client user preferences
    await sql`
      CREATE TABLE IF NOT EXISTS client_user_preferences (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID UNIQUE REFERENCES client_users(id) ON DELETE CASCADE,
        email_notifications BOOLEAN DEFAULT TRUE,
        project_updates BOOLEAN DEFAULT TRUE,
        document_notifications BOOLEAN DEFAULT TRUE,
        message_notifications BOOLEAN DEFAULT TRUE,
        theme VARCHAR(20) DEFAULT 'system',
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ client_user_preferences');

    // Client onboarding progress
    await sql`
      CREATE TABLE IF NOT EXISTS client_onboarding (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID UNIQUE REFERENCES client_users(id) ON DELETE CASCADE,
        welcome_seen BOOLEAN DEFAULT FALSE,
        profile_completed BOOLEAN DEFAULT FALSE,
        tour_completed BOOLEAN DEFAULT FALSE,
        first_project_viewed BOOLEAN DEFAULT FALSE,
        completed_at TIMESTAMP WITH TIME ZONE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ client_onboarding');

    // Client sessions (for token management)
    await sql`
      CREATE TABLE IF NOT EXISTS client_sessions (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id UUID REFERENCES client_users(id) ON DELETE CASCADE,
        refresh_token VARCHAR(255) UNIQUE NOT NULL,
        user_agent TEXT,
        ip_address VARCHAR(45),
        expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ client_sessions');

    // ============================================
    // PROJECT TABLES (Shared between admin and clients)
    // ============================================
    console.log('📦 Creating project tables...');

    // Projects table
    await sql`
      CREATE TABLE IF NOT EXISTS projects (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        reference VARCHAR(50) UNIQUE NOT NULL,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        sector VARCHAR(100),

        -- Project status: intake, scoping, active, review, complete, on_hold, cancelled
        status VARCHAR(50) DEFAULT 'intake',
        progress INTEGER DEFAULT 0,

        -- Dates
        start_date DATE,
        target_date DATE,
        completed_date DATE,

        -- Assignment
        assigned_admin UUID REFERENCES admin_users(id),

        -- Financials
        budget DECIMAL(15, 2),
        currency VARCHAR(3) DEFAULT 'ZAR',

        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ projects');

    // Project-Client assignments
    await sql`
      CREATE TABLE IF NOT EXISTS project_clients (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
        client_user_id UUID REFERENCES client_users(id) ON DELETE CASCADE,
        role VARCHAR(50) DEFAULT 'viewer',
        added_by UUID REFERENCES admin_users(id),
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(project_id, client_user_id)
      )
    `;
    console.log('  ✓ project_clients');

    // Project milestones
    await sql`
      CREATE TABLE IF NOT EXISTS project_milestones (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        status VARCHAR(50) DEFAULT 'pending',
        due_date DATE,
        completed_date DATE,
        sort_order INTEGER DEFAULT 0,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ project_milestones');

    // ============================================
    // DOCUMENT TABLES
    // ============================================
    console.log('📦 Creating document tables...');

    // Documents table
    await sql`
      CREATE TABLE IF NOT EXISTS documents (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        file_url TEXT NOT NULL,
        file_type VARCHAR(50),
        file_size INTEGER,
        version INTEGER DEFAULT 1,

        -- Document type: deliverable, draft, reference, input
        document_type VARCHAR(50) DEFAULT 'deliverable',

        -- Access control
        visible_to_client BOOLEAN DEFAULT FALSE,

        uploaded_by UUID,
        uploaded_by_type VARCHAR(10), -- 'admin' or 'client'

        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ documents');

    // ============================================
    // MESSAGING TABLES
    // ============================================
    console.log('📦 Creating messaging tables...');

    // Messages table
    await sql`
      CREATE TABLE IF NOT EXISTS messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        project_id UUID REFERENCES projects(id) ON DELETE CASCADE,

        sender_id UUID NOT NULL,
        sender_type VARCHAR(10) NOT NULL, -- 'admin' or 'client'

        content TEXT NOT NULL,

        -- Optional attachment
        attachment_url TEXT,
        attachment_name VARCHAR(255),

        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ messages');

    // Message read status
    await sql`
      CREATE TABLE IF NOT EXISTS message_reads (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
        reader_id UUID NOT NULL,
        reader_type VARCHAR(10) NOT NULL, -- 'admin' or 'client'
        read_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(message_id, reader_id, reader_type)
      )
    `;
    console.log('  ✓ message_reads');

    // ============================================
    // ACTIVITY LOG
    // ============================================
    console.log('📦 Creating activity tables...');

    await sql`
      CREATE TABLE IF NOT EXISTS activity_log (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        project_id UUID REFERENCES projects(id) ON DELETE SET NULL,

        actor_id UUID NOT NULL,
        actor_type VARCHAR(10) NOT NULL, -- 'admin', 'client', or 'system'

        action VARCHAR(100) NOT NULL,
        description TEXT,
        metadata JSONB,

        -- For filtering
        visible_to_client BOOLEAN DEFAULT FALSE,

        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('  ✓ activity_log');

    // ============================================
    // INDEXES
    // ============================================
    console.log('📦 Creating indexes...');

    await sql`CREATE INDEX IF NOT EXISTS idx_client_users_email ON client_users(email)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_client_users_status ON client_users(status)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_projects_status ON projects(status)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_projects_reference ON projects(reference)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_project_clients_user ON project_clients(client_user_id)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_documents_project ON documents(project_id)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_messages_project ON messages(project_id)`;
    await sql`CREATE INDEX IF NOT EXISTS idx_activity_log_project ON activity_log(project_id)`;
    console.log('  ✓ All indexes created');

    console.log('\n✅ Database initialization complete!');
    console.log('\nTables created:');
    console.log('  - admin_users');
    console.log('  - client_users');
    console.log('  - client_companies');
    console.log('  - client_company_members');
    console.log('  - client_user_preferences');
    console.log('  - client_onboarding');
    console.log('  - client_sessions');
    console.log('  - projects');
    console.log('  - project_clients');
    console.log('  - project_milestones');
    console.log('  - documents');
    console.log('  - messages');
    console.log('  - message_reads');
    console.log('  - activity_log');

  } catch (error) {
    console.error('\n❌ Database initialization failed:', error.message);
    process.exit(1);
  }
}

initDatabase();
