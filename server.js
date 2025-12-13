/**
 * JASPER API - Express Server
 * Wraps Vercel serverless functions for VPS deployment
 * Port: 3003
 */

import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load environment variables
// In production, load .env.production; in development, load .env.local or .env
const envFile = process.env.NODE_ENV === 'production' ? '.env.production' : '.env.local';
dotenv.config({ path: join(__dirname, envFile) });

const app = express();
const PORT = process.env.PORT || 3003;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Request logging
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.url}`);
  next();
});

// Import Vercel function handlers
import healthHandler from './api/health.js';
import contactHandler from './api/contact.js';
import adminAuthHandler from './api/admin/auth/[action].js';
import clientAuthHandler from './api/client/auth/[action].js';
import authHandler from './api/auth/[action].js';
import crmLeadsHandler from './api/crm/leads.js';
import crmIntakeHandler from './api/crm/intake.js';
import imailSendHandler from './api/imail/send.js';
import imailVerifyHandler from './api/imail/verify.js';
import notificationsHandler from './api/notifications/index.js';
import webhooksContactHandler from './api/webhooks/contact-form.js';

// Helper to adapt Vercel handlers to Express
function adaptHandler(handler) {
  return async (req, res) => {
    try {
      // Copy Express params to query for Vercel-style handlers
      req.query = { ...req.query, ...req.params };
      await handler(req, res);
    } catch (error) {
      console.error('Handler error:', error);
      if (!res.headersSent) {
        res.status(500).json({ error: 'Internal server error' });
      }
    }
  };
}

// ============================================
// ROUTES
// ============================================

// Health check
app.all('/health', adaptHandler(healthHandler));
app.all('/api/health', adaptHandler(healthHandler));

// Contact form
app.all('/contact', adaptHandler(contactHandler));
app.all('/api/contact', adaptHandler(contactHandler));

// Admin auth routes
app.all('/api/v1/admin/auth/:action', adaptHandler(adminAuthHandler));
app.all('/api/admin/auth/:action', adaptHandler(adminAuthHandler));

// Client auth routes
app.all('/api/client/auth/:action', adaptHandler(clientAuthHandler));

// Legacy auth routes (if any)
app.all('/auth/:action', adaptHandler(authHandler));
app.all('/api/auth/:action', adaptHandler(authHandler));

// CRM routes
app.all('/api/v1/crm/leads', adaptHandler(crmLeadsHandler));
app.all('/api/crm/leads', adaptHandler(crmLeadsHandler));
app.all('/api/v1/crm/intake', adaptHandler(crmIntakeHandler));
app.all('/api/crm/intake', adaptHandler(crmIntakeHandler));

// iMail routes
app.all('/imail/send', adaptHandler(imailSendHandler));
app.all('/api/imail/send', adaptHandler(imailSendHandler));
app.all('/imail/verify', adaptHandler(imailVerifyHandler));
app.all('/api/imail/verify', adaptHandler(imailVerifyHandler));

// Notifications
app.all('/api/v1/notifications', adaptHandler(notificationsHandler));
app.all('/api/notifications', adaptHandler(notificationsHandler));

// Webhooks
app.all('/api/v1/webhooks/contact-form', adaptHandler(webhooksContactHandler));
app.all('/api/webhooks/contact-form', adaptHandler(webhooksContactHandler));

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Not found',
    path: req.url,
    method: req.method
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`
============================================
JASPER API Server
============================================
Port: ${PORT}
Environment: ${process.env.NODE_ENV || 'development'}
Time: ${new Date().toISOString()}
============================================
  `);
});

export default app;
