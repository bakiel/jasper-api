// In-memory status store (for demo - use Redis/DB in production)
const statusStore = new Map();

export default async function handler(req, res) {
  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // API Key verification
  const apiKey = req.headers['x-api-key'] || req.headers['authorization']?.replace('Bearer ', '');
  if (apiKey !== process.env.IMAIL_API_KEY) {
    return res.status(401).json({ success: false, error: 'Invalid API key' });
  }

  // GET - Retrieve status
  if (req.method === 'GET') {
    const { trackingId } = req.query;

    if (!trackingId) {
      return res.status(400).json({ success: false, error: 'trackingId is required' });
    }

    const status = statusStore.get(trackingId);

    if (!status) {
      return res.status(404).json({
        success: false,
        error: 'Tracking ID not found',
        trackingId
      });
    }

    return res.status(200).json({
      success: true,
      ...status
    });
  }

  // POST - Update status (webhook receiver)
  if (req.method === 'POST') {
    const { trackingId, event, recipient, timestamp, metadata } = req.body;

    if (!trackingId || !event) {
      return res.status(400).json({ success: false, error: 'trackingId and event are required' });
    }

    const validEvents = ['sent', 'delivered', 'opened', 'clicked', 'bounced', 'complained', 'unsubscribed'];
    if (!validEvents.includes(event)) {
      return res.status(400).json({ success: false, error: `Invalid event. Must be one of: ${validEvents.join(', ')}` });
    }

    // Get or create status record
    let status = statusStore.get(trackingId) || {
      trackingId,
      events: [],
      currentStatus: 'pending',
      createdAt: new Date().toISOString()
    };

    // Add event
    status.events.push({
      event,
      recipient,
      timestamp: timestamp || new Date().toISOString(),
      metadata
    });

    // Update current status
    status.currentStatus = event;
    status.updatedAt = new Date().toISOString();

    // Store
    statusStore.set(trackingId, status);

    // Trigger webhook if configured
    if (process.env.IMAIL_WEBHOOK_URL) {
      try {
        await fetch(process.env.IMAIL_WEBHOOK_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-JASPER-Signature': generateSignature(status)
          },
          body: JSON.stringify({
            type: 'email.status',
            ...status
          })
        });
      } catch (err) {
        console.error('Webhook delivery failed:', err.message);
      }
    }

    return res.status(200).json({
      success: true,
      message: 'Status updated',
      trackingId,
      currentStatus: status.currentStatus
    });
  }

  return res.status(405).json({ success: false, error: 'Method not allowed' });
}

function generateSignature(payload) {
  const crypto = require('crypto');
  const secret = process.env.IMAIL_WEBHOOK_SECRET || 'jasper-imail-secret';
  return crypto
    .createHmac('sha256', secret)
    .update(JSON.stringify(payload))
    .digest('hex');
}
