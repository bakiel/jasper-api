// CRM Leads API - Self-hosted intake system
// Handles lead management for JASPER Financial Architecture
import { jwtVerify } from 'jose';

const SECRET_KEY = process.env.SECRET_KEY || 'jasper-default-secret-key-change-in-production';

function getSecretKey() {
  return new TextEncoder().encode(SECRET_KEY);
}

// Verify JWT token from Authorization header
async function verifyAuth(req) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }

  const token = authHeader.substring(7);
  try {
    const { payload } = await jwtVerify(token, getSecretKey());
    return payload;
  } catch (error) {
    return null;
  }
}

// In-memory store (use PostgreSQL/MongoDB in production)
// For serverless, consider Vercel KV, Neon, or PlanetScale
let leads = [];

// Generate lead ID
function generateId() {
  return `LEAD-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substr(2, 4).toUpperCase()}`;
}

// Lead statuses
const LEAD_STATUSES = ['new', 'contacted', 'qualified', 'proposal_sent', 'negotiation', 'won', 'lost'];

// Lead sources
const LEAD_SOURCES = ['website', 'referral', 'linkedin', 'email', 'cold_call', 'conference', 'other'];

export default async function handler(req, res) {
  // CORS - restrict to known origins
  const allowedOrigins = ['https://jasperfinance.org', 'https://portal.jasperfinance.org', 'http://localhost:3000'];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-User-Id');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Require authentication for all operations
  const user = await verifyAuth(req);
  if (!user) {
    return res.status(401).json({ success: false, message: 'Authentication required' });
  }

  // GET - List all leads or get specific lead
  if (req.method === 'GET') {
    const { id, status, source, search, page = 1, limit = 20 } = req.query;

    // Get specific lead by ID
    if (id) {
      const lead = leads.find(l => l.id === id);
      if (!lead) {
        return res.status(404).json({ success: false, message: 'Lead not found' });
      }
      return res.status(200).json({ success: true, lead });
    }

    // Filter leads
    let filteredLeads = [...leads];

    if (status) {
      filteredLeads = filteredLeads.filter(l => l.status === status);
    }

    if (source) {
      filteredLeads = filteredLeads.filter(l => l.source === source);
    }

    if (search) {
      const searchLower = search.toLowerCase();
      filteredLeads = filteredLeads.filter(l =>
        l.name.toLowerCase().includes(searchLower) ||
        l.company.toLowerCase().includes(searchLower) ||
        l.email.toLowerCase().includes(searchLower)
      );
    }

    // Pagination
    const startIndex = (page - 1) * limit;
    const paginatedLeads = filteredLeads.slice(startIndex, startIndex + parseInt(limit));

    // Statistics
    const stats = {
      total: filteredLeads.length,
      byStatus: LEAD_STATUSES.reduce((acc, s) => {
        acc[s] = leads.filter(l => l.status === s).length;
        return acc;
      }, {}),
      bySource: LEAD_SOURCES.reduce((acc, s) => {
        acc[s] = leads.filter(l => l.source === s).length;
        return acc;
      }, {}),
    };

    return res.status(200).json({
      success: true,
      leads: paginatedLeads,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: filteredLeads.length,
        totalPages: Math.ceil(filteredLeads.length / limit),
      },
      stats,
    });
  }

  // POST - Create new lead
  if (req.method === 'POST') {
    try {
      const {
        name,
        email,
        company,
        phone,
        sector,
        fundingStage,
        fundingAmount,
        message,
        source = 'website',
        notes,
      } = req.body;

      // Validation
      if (!name || !email || !company) {
        return res.status(400).json({
          success: false,
          message: 'Name, email, and company are required',
        });
      }

      // Check for duplicate email
      const existingLead = leads.find(l => l.email.toLowerCase() === email.toLowerCase());
      if (existingLead) {
        return res.status(409).json({
          success: false,
          message: 'A lead with this email already exists',
          existingLeadId: existingLead.id,
        });
      }

      const newLead = {
        id: generateId(),
        name,
        email: email.toLowerCase(),
        company,
        phone: phone || null,
        sector: sector || null,
        fundingStage: fundingStage || null,
        fundingAmount: fundingAmount || null,
        message: message || null,
        source,
        status: 'new',
        notes: notes || [],
        assignedTo: null,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        lastContactedAt: null,
        tags: [],
        value: null,
      };

      leads.unshift(newLead);

      return res.status(201).json({
        success: true,
        lead: newLead,
      });
    } catch (error) {
      console.error('Create lead error:', error);
      return res.status(500).json({
        success: false,
        message: 'Failed to create lead',
      });
    }
  }

  // PUT/PATCH - Update lead
  if (req.method === 'PUT' || req.method === 'PATCH') {
    try {
      const { id } = req.query;
      const updates = req.body;

      if (!id) {
        return res.status(400).json({
          success: false,
          message: 'Lead ID is required',
        });
      }

      const leadIndex = leads.findIndex(l => l.id === id);
      if (leadIndex === -1) {
        return res.status(404).json({
          success: false,
          message: 'Lead not found',
        });
      }

      // Validate status if provided
      if (updates.status && !LEAD_STATUSES.includes(updates.status)) {
        return res.status(400).json({
          success: false,
          message: `Invalid status. Must be one of: ${LEAD_STATUSES.join(', ')}`,
        });
      }

      // Update lead
      leads[leadIndex] = {
        ...leads[leadIndex],
        ...updates,
        updatedAt: new Date().toISOString(),
      };

      return res.status(200).json({
        success: true,
        lead: leads[leadIndex],
      });
    } catch (error) {
      console.error('Update lead error:', error);
      return res.status(500).json({
        success: false,
        message: 'Failed to update lead',
      });
    }
  }

  // DELETE - Delete lead
  if (req.method === 'DELETE') {
    try {
      const { id } = req.query;

      if (!id) {
        return res.status(400).json({
          success: false,
          message: 'Lead ID is required',
        });
      }

      const leadIndex = leads.findIndex(l => l.id === id);
      if (leadIndex === -1) {
        return res.status(404).json({
          success: false,
          message: 'Lead not found',
        });
      }

      const deletedLead = leads.splice(leadIndex, 1)[0];

      return res.status(200).json({
        success: true,
        message: 'Lead deleted',
        lead: deletedLead,
      });
    } catch (error) {
      console.error('Delete lead error:', error);
      return res.status(500).json({
        success: false,
        message: 'Failed to delete lead',
      });
    }
  }

  return res.status(405).json({
    success: false,
    message: 'Method not allowed',
  });
}

// Export for use in other endpoints
export function getLeads() {
  return leads;
}

export function addLead(leadData) {
  const newLead = {
    id: generateId(),
    ...leadData,
    status: leadData.status || 'new',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
  leads.unshift(newLead);
  return newLead;
}
