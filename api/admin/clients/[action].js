// Admin client management endpoint - handles client user management
import { sql } from '../../lib/db.js';

// Simple auth check (extracts user from Bearer token)
function authenticateAdmin(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  const token = authHeader.substring(7);
  try {
    const sessionData = JSON.parse(Buffer.from(token, 'base64').toString());
    if (sessionData.exp < Date.now()) {
      return null;
    }
    return sessionData;
  } catch {
    return null;
  }
}

export default async function handler(req, res) {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Authenticate admin
  const admin = authenticateAdmin(req);
  if (!admin) {
    return res.status(401).json({ detail: 'Not authenticated' });
  }

  const { action } = req.query;

  // Route to appropriate handler
  switch (action) {
    case 'list':
      return handleList(req, res);
    case 'pending':
      return handlePending(req, res);
    case 'approve':
      return handleApprove(req, res, admin);
    case 'reject':
      return handleReject(req, res, admin);
    case 'stats':
      return handleStats(req, res);
    default:
      // Check if action is a UUID (client ID)
      if (action && action.length > 10) {
        return handleGetClient(req, res, action);
      }
      return res.status(404).json({ error: 'Not found' });
  }
}

// List all clients with pagination
async function handleList(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const page = parseInt(req.query.page) || 1;
    const pageSize = parseInt(req.query.page_size) || 20;
    const status = req.query.status; // Filter by status
    const search = req.query.search; // Search by name/email

    const offset = (page - 1) * pageSize;

    let whereClause = '';
    const params = [];

    if (status) {
      params.push(status);
      whereClause = `WHERE status = $${params.length}`;
    }

    if (search) {
      params.push(`%${search}%`);
      const searchClause = `(full_name ILIKE $${params.length} OR email ILIKE $${params.length})`;
      whereClause = whereClause
        ? `${whereClause} AND ${searchClause}`
        : `WHERE ${searchClause}`;
    }

    // Get total count
    const countQuery = `SELECT COUNT(*) as count FROM client_users ${whereClause}`;
    const countResult = await sql(countQuery, params);
    const total = parseInt(countResult[0]?.count || 0);

    // Get clients
    params.push(pageSize, offset);
    const clientsQuery = `
      SELECT
        id, email, full_name, company_name, phone,
        avatar_url, google_id, linkedin_id,
        email_verified, status, approved_at,
        last_login_at, login_count, created_at, updated_at
      FROM client_users
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT $${params.length - 1} OFFSET $${params.length}
    `;

    const clients = await sql(clientsQuery, params);

    return res.status(200).json({
      clients: clients.map(c => ({
        id: c.id,
        email: c.email,
        name: c.full_name,
        full_name: c.full_name,
        company: c.company_name,
        company_name: c.company_name,
        phone: c.phone,
        avatar_url: c.avatar_url,
        has_google: !!c.google_id,
        has_linkedin: !!c.linkedin_id,
        email_verified: c.email_verified,
        status: c.status,
        approved_at: c.approved_at,
        last_login: c.last_login_at,
        login_count: c.login_count || 0,
        created_at: c.created_at,
        updated_at: c.updated_at,
      })),
      total,
      page,
      page_size: pageSize,
      total_pages: Math.ceil(total / pageSize),
    });
  } catch (error) {
    console.error('Error listing clients:', error);
    return res.status(500).json({ detail: 'Failed to list clients' });
  }
}

// List pending approval clients
async function handlePending(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const clients = await sql`
      SELECT
        id, email, full_name, company_name, phone,
        avatar_url, google_id, linkedin_id,
        email_verified, status, created_at
      FROM client_users
      WHERE status = 'pending_approval'
      ORDER BY created_at DESC
    `;

    return res.status(200).json({
      clients: clients.map(c => ({
        id: c.id,
        email: c.email,
        name: c.full_name,
        full_name: c.full_name,
        company: c.company_name,
        company_name: c.company_name,
        phone: c.phone,
        avatar_url: c.avatar_url,
        has_google: !!c.google_id,
        has_linkedin: !!c.linkedin_id,
        email_verified: c.email_verified,
        status: c.status,
        created_at: c.created_at,
      })),
      total: clients.length,
    });
  } catch (error) {
    console.error('Error listing pending clients:', error);
    return res.status(500).json({ detail: 'Failed to list pending clients' });
  }
}

// Approve a client
async function handleApprove(req, res, admin) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { client_id } = req.body;

    if (!client_id) {
      return res.status(400).json({ detail: 'Client ID required' });
    }

    // Update client status
    const result = await sql`
      UPDATE client_users
      SET status = 'active',
          approved_at = NOW(),
          updated_at = NOW()
      WHERE id = ${client_id}
      RETURNING id, email, full_name, status
    `;

    if (result.length === 0) {
      return res.status(404).json({ detail: 'Client not found' });
    }

    const client = result[0];

    // TODO: Send approval email to client
    // await sendApprovalEmail(client.email, client.full_name);

    return res.status(200).json({
      success: true,
      message: `Client ${client.full_name} approved`,
      client: {
        id: client.id,
        email: client.email,
        name: client.full_name,
        status: client.status,
      },
    });
  } catch (error) {
    console.error('Error approving client:', error);
    return res.status(500).json({ detail: 'Failed to approve client' });
  }
}

// Reject a client
async function handleReject(req, res, admin) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { client_id, reason } = req.body;

    if (!client_id) {
      return res.status(400).json({ detail: 'Client ID required' });
    }

    // Update client status
    const result = await sql`
      UPDATE client_users
      SET status = 'rejected',
          updated_at = NOW()
      WHERE id = ${client_id}
      RETURNING id, email, full_name, status
    `;

    if (result.length === 0) {
      return res.status(404).json({ detail: 'Client not found' });
    }

    const client = result[0];

    // TODO: Send rejection email to client
    // await sendRejectionEmail(client.email, client.full_name, reason);

    return res.status(200).json({
      success: true,
      message: `Client ${client.full_name} rejected`,
      client: {
        id: client.id,
        email: client.email,
        name: client.full_name,
        status: client.status,
      },
    });
  } catch (error) {
    console.error('Error rejecting client:', error);
    return res.status(500).json({ detail: 'Failed to reject client' });
  }
}

// Get client statistics
async function handleStats(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const stats = await sql`
      SELECT
        COUNT(*) FILTER (WHERE status = 'active') as active_count,
        COUNT(*) FILTER (WHERE status = 'pending_approval') as pending_count,
        COUNT(*) FILTER (WHERE status = 'pending_verification') as verification_count,
        COUNT(*) FILTER (WHERE status = 'rejected') as rejected_count,
        COUNT(*) as total_count,
        COUNT(*) FILTER (WHERE created_at > NOW() - INTERVAL '7 days') as new_this_week,
        COUNT(*) FILTER (WHERE last_login_at > NOW() - INTERVAL '24 hours') as active_today
      FROM client_users
    `;

    const s = stats[0] || {};

    return res.status(200).json({
      active: parseInt(s.active_count) || 0,
      pending_approval: parseInt(s.pending_count) || 0,
      pending_verification: parseInt(s.verification_count) || 0,
      rejected: parseInt(s.rejected_count) || 0,
      total: parseInt(s.total_count) || 0,
      new_this_week: parseInt(s.new_this_week) || 0,
      active_today: parseInt(s.active_today) || 0,
    });
  } catch (error) {
    console.error('Error getting client stats:', error);
    return res.status(500).json({ detail: 'Failed to get stats' });
  }
}

// Get single client by ID
async function handleGetClient(req, res, clientId) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const result = await sql`
      SELECT
        u.id, u.email, u.full_name, u.company_name, u.phone,
        u.avatar_url, u.google_id, u.linkedin_id,
        u.email_verified, u.status, u.approved_at, u.approved_by,
        u.last_login_at, u.login_count, u.failed_login_attempts,
        u.created_at, u.updated_at,
        o.completed as onboarding_completed,
        o.current_step as onboarding_step,
        p.email_notifications, p.theme, p.timezone
      FROM client_users u
      LEFT JOIN client_onboarding o ON o.user_id = u.id
      LEFT JOIN client_user_preferences p ON p.user_id = u.id
      WHERE u.id = ${clientId}
    `;

    if (result.length === 0) {
      return res.status(404).json({ detail: 'Client not found' });
    }

    const c = result[0];

    return res.status(200).json({
      id: c.id,
      email: c.email,
      name: c.full_name,
      full_name: c.full_name,
      company: c.company_name,
      company_name: c.company_name,
      phone: c.phone,
      avatar_url: c.avatar_url,
      has_google: !!c.google_id,
      has_linkedin: !!c.linkedin_id,
      email_verified: c.email_verified,
      status: c.status,
      approved_at: c.approved_at,
      approved_by: c.approved_by,
      last_login: c.last_login_at,
      login_count: c.login_count || 0,
      failed_login_attempts: c.failed_login_attempts || 0,
      created_at: c.created_at,
      updated_at: c.updated_at,
      onboarding: {
        completed: c.onboarding_completed || false,
        current_step: c.onboarding_step || 1,
      },
      preferences: {
        email_notifications: c.email_notifications !== false,
        theme: c.theme || 'dark',
        timezone: c.timezone || 'Africa/Johannesburg',
      },
    });
  } catch (error) {
    console.error('Error getting client:', error);
    return res.status(500).json({ detail: 'Failed to get client' });
  }
}
