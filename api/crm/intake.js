// CRM Intake Form API - Public endpoint for lead capture
// This replaces Tally/Typeform with self-hosted solution
// Routes to VPS CRM at 72.61.201.237:8001

// VPS CRM API URL
const CRM_API_URL = process.env.CRM_API_URL || 'http://72.61.201.237:8001';

// Map website values (hyphens) to CRM values (underscores)
const SECTOR_MAP = {
  'renewable-energy': 'renewable_energy',
  'data-centres': 'data_centres',
  'agri-industrial': 'agri_industrial',
  'climate-finance': 'climate_finance',
  'technology': 'technology',
  'manufacturing': 'manufacturing',
  'healthcare': 'healthcare',
  'infrastructure': 'infrastructure',
  'other': 'other',
};

const FUNDING_STAGE_MAP = {
  'seed': 'seed',
  'series-a': 'series_a',
  'series-b': 'series_b',
  'growth': 'growth',
  'expansion': 'expansion',
  'established': 'established',
  'other': 'other',
};

const FUNDING_AMOUNT_MAP = {
  'under-1m': 'under_1m',
  '1m-10m': '1m_10m',
  '10m-50m': '10m_50m',
  '50m-100m': '50m_100m',
  '100m-500m': '100m_500m',
  'over-500m': 'over_500m',
};

// Generate lead ID
function generateLeadId() {
  return `LEAD-${Date.now().toString(36).toUpperCase()}-${Math.random().toString(36).substr(2, 4).toUpperCase()}`;
}

// Sector options for the intake form
const SECTORS = [
  { value: 'renewable-energy', label: 'Renewable Energy' },
  { value: 'data-centres', label: 'Data Centres' },
  { value: 'agri-industrial', label: 'Agri-Industrial' },
  { value: 'climate-finance', label: 'Climate Finance' },
  { value: 'technology', label: 'Technology' },
  { value: 'manufacturing', label: 'Manufacturing' },
  { value: 'healthcare', label: 'Healthcare' },
  { value: 'infrastructure', label: 'Infrastructure' },
  { value: 'other', label: 'Other' },
];

// Funding stage options
const FUNDING_STAGES = [
  { value: 'seed', label: 'Seed / Pre-Revenue' },
  { value: 'series-a', label: 'Series A' },
  { value: 'series-b', label: 'Series B+' },
  { value: 'growth', label: 'Growth Stage' },
  { value: 'expansion', label: 'Expansion' },
  { value: 'established', label: 'Established Business' },
  { value: 'other', label: 'Other' },
];

// Funding amount ranges
const FUNDING_RANGES = [
  { value: 'under-1m', label: 'Under R1 million' },
  { value: '1m-10m', label: 'R1 - R10 million' },
  { value: '10m-50m', label: 'R10 - R50 million' },
  { value: '50m-100m', label: 'R50 - R100 million' },
  { value: '100m-500m', label: 'R100 - R500 million' },
  { value: 'over-500m', label: 'Over R500 million' },
];

// Rate limiting
const rateLimitMap = new Map();
const RATE_LIMIT = 3; // submissions per IP
const RATE_WINDOW = 60 * 60 * 1000; // 1 hour

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap.get(ip);

  if (!record || now - record.timestamp > RATE_WINDOW) {
    rateLimitMap.set(ip, { count: 1, timestamp: now });
    return true;
  }

  if (record.count >= RATE_LIMIT) {
    return false;
  }

  record.count++;
  return true;
}

// Sanitize input
function sanitize(str) {
  if (!str) return '';
  return str.trim().replace(/[<>]/g, '').slice(0, 5000);
}

// Validate email
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

export default async function handler(req, res) {
  // CORS - allow embedding from marketing site
  const allowedOrigins = [
    'https://jasperfinance.org',
    'https://www.jasperfinance.org',
    'https://portal.jasperfinance.org',
    'http://localhost:3000',
    'http://localhost:5173',
  ];

  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // GET - Return form configuration
  if (req.method === 'GET') {
    return res.status(200).json({
      success: true,
      formConfig: {
        sectors: SECTORS,
        fundingStages: FUNDING_STAGES,
        fundingRanges: FUNDING_RANGES,
        fields: [
          { name: 'name', type: 'text', required: true, label: 'Full Name' },
          { name: 'email', type: 'email', required: true, label: 'Email Address' },
          { name: 'company', type: 'text', required: true, label: 'Company Name' },
          { name: 'phone', type: 'tel', required: false, label: 'Phone Number' },
          { name: 'sector', type: 'select', required: true, label: 'Industry Sector', options: SECTORS },
          { name: 'fundingStage', type: 'select', required: true, label: 'Funding Stage', options: FUNDING_STAGES },
          { name: 'fundingAmount', type: 'select', required: false, label: 'Funding Amount Sought', options: FUNDING_RANGES },
          { name: 'message', type: 'textarea', required: true, label: 'Project Description', minLength: 50 },
        ],
      },
    });
  }

  // POST - Submit intake form
  if (req.method === 'POST') {
    // Rate limiting
    const ip = req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown';
    if (!checkRateLimit(ip)) {
      return res.status(429).json({
        success: false,
        message: 'Too many submissions. Please try again later.',
      });
    }

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
        referralSource,
      } = req.body;

      // Validation
      const errors = {};

      if (!name?.trim()) {
        errors.name = 'Full name is required';
      }

      if (!email?.trim() || !isValidEmail(email)) {
        errors.email = 'Valid email address is required';
      }

      if (!company?.trim()) {
        errors.company = 'Company name is required';
      }

      if (!sector?.trim()) {
        errors.sector = 'Industry sector is required';
      }

      if (!fundingStage?.trim()) {
        errors.fundingStage = 'Funding stage is required';
      }

      if (!message?.trim() || message.length < 50) {
        errors.message = 'Project description must be at least 50 characters';
      }

      if (Object.keys(errors).length > 0) {
        return res.status(422).json({
          success: false,
          message: 'Validation failed',
          errors,
        });
      }

      // Map values for VPS CRM (underscores instead of hyphens)
      const mappedSector = SECTOR_MAP[sector] || sector;
      const mappedFundingStage = FUNDING_STAGE_MAP[fundingStage] || fundingStage;
      const mappedFundingAmount = fundingAmount ? (FUNDING_AMOUNT_MAP[fundingAmount] || fundingAmount) : null;

      // Submit to VPS CRM intake endpoint
      let crmSuccess = false;
      let leadReference = null;

      try {
        const crmResponse = await fetch(`${CRM_API_URL}/api/v1/intake`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            name: sanitize(name),
            email: sanitize(email).toLowerCase(),
            company: sanitize(company),
            phone: sanitize(phone) || null,
            sector: mappedSector,
            funding_stage: mappedFundingStage,
            funding_amount: mappedFundingAmount,
            message: sanitize(message),
            referral_source: referralSource ? sanitize(referralSource) : null,
          }),
        });

        if (crmResponse.ok) {
          const crmResult = await crmResponse.json();
          crmSuccess = true;
          leadReference = crmResult.reference;
          console.log(`CRM lead created: ${leadReference} for ${email}`);
        } else {
          const errorText = await crmResponse.text();
          console.error(`CRM creation failed: ${crmResponse.status} - ${errorText}`);
          // Generate fallback reference
          leadReference = generateLeadId();
        }
      } catch (crmError) {
        console.error('CRM integration error:', crmError.message);
        // Generate fallback reference
        leadReference = generateLeadId();
      }

      // Return success (CRM handles notification creation)
      return res.status(201).json({
        success: true,
        message: 'Thank you for your submission. Our team will review your enquiry and respond within 24-48 hours.',
        reference: leadReference,
        crm_synced: crmSuccess,
      });

    } catch (error) {
      console.error('Intake form error:', error);
      return res.status(500).json({
        success: false,
        message: 'An error occurred. Please try again or contact us directly.',
      });
    }
  }

  return res.status(405).json({
    success: false,
    message: 'Method not allowed',
  });
}
