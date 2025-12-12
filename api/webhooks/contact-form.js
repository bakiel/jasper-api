// Webhook: Contact Form Submission
// Creates CRM record + notification when contact form is submitted

import { addNotification } from '../notifications/index.js';

// In-memory CRM store (use PostgreSQL/MongoDB in production)
let crmRecords = [];

function generateId() {
  return `lead-${Date.now().toString(36)}-${Math.random().toString(36).substr(2, 5)}`;
}

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Webhook-Secret');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ success: false, message: 'Method not allowed' });
  }

  // Verify webhook secret (optional security)
  const webhookSecret = process.env.WEBHOOK_SECRET;
  const providedSecret = req.headers['x-webhook-secret'];

  if (webhookSecret && providedSecret !== webhookSecret) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const {
      name,
      email,
      company,
      phone,
      sector,
      funding_stage,
      funding_amount,
      message,
      source,
      reference,
    } = req.body;

    // Create CRM record
    const crmRecord = {
      id: generateId(),
      type: 'lead',
      status: 'new',
      name,
      email,
      company,
      phone,
      sector,
      fundingStage: funding_stage,
      fundingAmount: funding_amount,
      message,
      source: source || 'website',
      reference,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };

    crmRecords.push(crmRecord);

    // Create notification for admin
    const notification = addNotification({
      type: 'client',
      title: 'New Lead Received',
      message: `${company} (${name}) submitted an enquiry via ${source || 'website'}`,
      link: '/clients',
      priority: 'medium',
      userId: 'admin',
    });

    console.log(`CRM record created: ${crmRecord.id}`);
    console.log(`Notification created: ${notification.id}`);

    return res.status(201).json({
      success: true,
      crmId: crmRecord.id,
      notificationId: notification.id,
    });
  } catch (error) {
    console.error('Webhook error:', error);
    return res.status(500).json({
      success: false,
      message: 'Internal server error',
    });
  }
}

// Export CRM records for other endpoints
export function getCrmRecords() {
  return crmRecords;
}

export function updateCrmRecord(id, updates) {
  const index = crmRecords.findIndex(r => r.id === id);
  if (index !== -1) {
    crmRecords[index] = { ...crmRecords[index], ...updates, updatedAt: new Date().toISOString() };
    return crmRecords[index];
  }
  return null;
}
