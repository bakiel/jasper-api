// Email service for verification and notifications
import nodemailer from 'nodemailer';

// Create transporter using environment variables
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.hostinger.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// Email templates
const templates = {
  verification: (name, code) => ({
    subject: 'Verify your JASPER Client Portal account',
    html: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Your Email</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0F172A; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0F172A; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #1E293B; border-radius: 16px; overflow: hidden;">
          <!-- Header -->
          <tr>
            <td style="padding: 40px 40px 30px; text-align: center; border-bottom: 1px solid #334155;">
              <img src="https://jasperfinance.org/images/jasper-icon.png" alt="JASPER" width="60" style="margin-bottom: 16px;">
              <h1 style="margin: 0; color: #E2E8F0; font-size: 24px; font-weight: 600;">JASPER</h1>
              <p style="margin: 4px 0 0; color: #94A3B8; font-size: 12px; letter-spacing: 2px;">CLIENT PORTAL</p>
            </td>
          </tr>

          <!-- Content -->
          <tr>
            <td style="padding: 40px;">
              <h2 style="margin: 0 0 16px; color: #E2E8F0; font-size: 20px; font-weight: 600;">Verify your email address</h2>
              <p style="margin: 0 0 24px; color: #94A3B8; font-size: 15px; line-height: 1.6;">
                Hi ${name},<br><br>
                Welcome to JASPER! Please use the verification code below to complete your registration:
              </p>

              <!-- Code Box -->
              <div style="background-color: #0F172A; border-radius: 12px; padding: 24px; text-align: center; margin-bottom: 24px;">
                <p style="margin: 0 0 8px; color: #94A3B8; font-size: 12px; text-transform: uppercase; letter-spacing: 1px;">Verification Code</p>
                <p style="margin: 0; color: #3DA872; font-size: 36px; font-weight: 700; letter-spacing: 8px;">${code}</p>
              </div>

              <p style="margin: 0 0 8px; color: #64748B; font-size: 13px;">
                This code will expire in <strong style="color: #94A3B8;">15 minutes</strong>.
              </p>
              <p style="margin: 0; color: #64748B; font-size: 13px;">
                If you didn't create an account, you can safely ignore this email.
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 24px 40px; background-color: #0F172A; border-top: 1px solid #334155;">
              <p style="margin: 0; color: #64748B; font-size: 12px; text-align: center;">
                &copy; ${new Date().getFullYear()} JASPER Financial Architecture. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    `,
    text: `
JASPER Client Portal - Email Verification

Hi ${name},

Welcome to JASPER! Please use the verification code below to complete your registration:

Verification Code: ${code}

This code will expire in 15 minutes.

If you didn't create an account, you can safely ignore this email.

---
JASPER Financial Architecture
    `
  }),

  passwordReset: (name, resetLink) => ({
    subject: 'Reset your JASPER Client Portal password',
    html: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Your Password</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0F172A; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0F172A; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #1E293B; border-radius: 16px; overflow: hidden;">
          <!-- Header -->
          <tr>
            <td style="padding: 40px 40px 30px; text-align: center; border-bottom: 1px solid #334155;">
              <img src="https://jasperfinance.org/images/jasper-icon.png" alt="JASPER" width="60" style="margin-bottom: 16px;">
              <h1 style="margin: 0; color: #E2E8F0; font-size: 24px; font-weight: 600;">JASPER</h1>
              <p style="margin: 4px 0 0; color: #94A3B8; font-size: 12px; letter-spacing: 2px;">CLIENT PORTAL</p>
            </td>
          </tr>

          <!-- Content -->
          <tr>
            <td style="padding: 40px;">
              <h2 style="margin: 0 0 16px; color: #E2E8F0; font-size: 20px; font-weight: 600;">Reset your password</h2>
              <p style="margin: 0 0 24px; color: #94A3B8; font-size: 15px; line-height: 1.6;">
                Hi ${name},<br><br>
                We received a request to reset your password. Click the button below to create a new password:
              </p>

              <!-- Button -->
              <div style="text-align: center; margin-bottom: 24px;">
                <a href="${resetLink}" style="display: inline-block; background-color: #3DA872; color: white; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 15px;">
                  Reset Password
                </a>
              </div>

              <p style="margin: 0 0 16px; color: #64748B; font-size: 13px;">
                This link will expire in <strong style="color: #94A3B8;">1 hour</strong>.
              </p>

              <p style="margin: 0 0 8px; color: #64748B; font-size: 13px;">
                If you didn't request a password reset, you can safely ignore this email. Your password will not be changed.
              </p>

              <p style="margin: 24px 0 0; padding-top: 24px; border-top: 1px solid #334155; color: #64748B; font-size: 12px;">
                If the button doesn't work, copy and paste this link into your browser:<br>
                <a href="${resetLink}" style="color: #3DA872; word-break: break-all;">${resetLink}</a>
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 24px 40px; background-color: #0F172A; border-top: 1px solid #334155;">
              <p style="margin: 0; color: #64748B; font-size: 12px; text-align: center;">
                &copy; ${new Date().getFullYear()} JASPER Financial Architecture. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    `,
    text: `
JASPER Client Portal - Password Reset

Hi ${name},

We received a request to reset your password. Click the link below to create a new password:

${resetLink}

This link will expire in 1 hour.

If you didn't request a password reset, you can safely ignore this email.

---
JASPER Financial Architecture
    `
  }),

  welcomeApproved: (name) => ({
    subject: 'Your JASPER Client Portal account has been approved!',
    html: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Account Approved</title>
</head>
<body style="margin: 0; padding: 0; background-color: #0F172A; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #0F172A; padding: 40px 20px;">
    <tr>
      <td align="center">
        <table width="600" cellpadding="0" cellspacing="0" style="background-color: #1E293B; border-radius: 16px; overflow: hidden;">
          <!-- Header -->
          <tr>
            <td style="padding: 40px 40px 30px; text-align: center; border-bottom: 1px solid #334155;">
              <img src="https://jasperfinance.org/images/jasper-icon.png" alt="JASPER" width="60" style="margin-bottom: 16px;">
              <h1 style="margin: 0; color: #E2E8F0; font-size: 24px; font-weight: 600;">JASPER</h1>
              <p style="margin: 4px 0 0; color: #94A3B8; font-size: 12px; letter-spacing: 2px;">CLIENT PORTAL</p>
            </td>
          </tr>

          <!-- Content -->
          <tr>
            <td style="padding: 40px;">
              <div style="text-align: center; margin-bottom: 24px;">
                <div style="display: inline-block; background-color: #3DA872; border-radius: 50%; padding: 16px; margin-bottom: 16px;">
                  <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="white" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                </div>
              </div>

              <h2 style="margin: 0 0 16px; color: #E2E8F0; font-size: 20px; font-weight: 600; text-align: center;">Your account has been approved!</h2>
              <p style="margin: 0 0 24px; color: #94A3B8; font-size: 15px; line-height: 1.6; text-align: center;">
                Hi ${name},<br><br>
                Great news! Your JASPER Client Portal account has been approved. You can now access all features of the portal.
              </p>

              <!-- Button -->
              <div style="text-align: center; margin-bottom: 24px;">
                <a href="https://client.jasperfinance.org" style="display: inline-block; background-color: #3DA872; color: white; text-decoration: none; padding: 14px 32px; border-radius: 8px; font-weight: 600; font-size: 15px;">
                  Go to Portal
                </a>
              </div>

              <p style="margin: 0; color: #64748B; font-size: 13px; text-align: center;">
                We're excited to have you on board!
              </p>
            </td>
          </tr>

          <!-- Footer -->
          <tr>
            <td style="padding: 24px 40px; background-color: #0F172A; border-top: 1px solid #334155;">
              <p style="margin: 0; color: #64748B; font-size: 12px; text-align: center;">
                &copy; ${new Date().getFullYear()} JASPER Financial Architecture. All rights reserved.
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>
    `,
    text: `
JASPER Client Portal - Account Approved

Hi ${name},

Great news! Your JASPER Client Portal account has been approved. You can now access all features of the portal.

Visit https://client.jasperfinance.org to get started.

We're excited to have you on board!

---
JASPER Financial Architecture
    `
  }),

  newRegistrationNotification: (userName, userEmail, companyName) => ({
    subject: `New Client Registration: ${userName}`,
    html: `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>New Registration</title>
</head>
<body style="margin: 0; padding: 20px; background-color: #f5f5f5; font-family: Arial, sans-serif;">
  <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px;">
    <h2 style="color: #1E3A4C; margin-top: 0;">New Client Registration</h2>
    <p>A new client has registered on the JASPER Client Portal:</p>
    <table style="width: 100%; border-collapse: collapse; margin: 20px 0;">
      <tr>
        <td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Name:</td>
        <td style="padding: 8px; border-bottom: 1px solid #eee;">${userName}</td>
      </tr>
      <tr>
        <td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Email:</td>
        <td style="padding: 8px; border-bottom: 1px solid #eee;">${userEmail}</td>
      </tr>
      <tr>
        <td style="padding: 8px; border-bottom: 1px solid #eee; font-weight: bold;">Company:</td>
        <td style="padding: 8px; border-bottom: 1px solid #eee;">${companyName || 'Not provided'}</td>
      </tr>
    </table>
    <p>Please review and approve this registration in the admin portal.</p>
    <a href="https://portal.jasperfinance.org/admin/clients" style="display: inline-block; background-color: #3DA872; color: white; text-decoration: none; padding: 12px 24px; border-radius: 6px; margin-top: 10px;">
      Review Registration
    </a>
  </div>
</body>
</html>
    `,
    text: `
New Client Registration

A new client has registered on the JASPER Client Portal:

Name: ${userName}
Email: ${userEmail}
Company: ${companyName || 'Not provided'}

Please review and approve this registration in the admin portal.
    `
  })
};

// Send email function
export async function sendEmail(to, template, ...args) {
  const emailContent = templates[template](...args);

  const mailOptions = {
    from: `"JASPER Client Portal" <${process.env.SMTP_USER || 'noreply@jasperfinance.org'}>`,
    to,
    subject: emailContent.subject,
    html: emailContent.html,
    text: emailContent.text,
  };

  try {
    const info = await transporter.sendMail(mailOptions);
    console.log('Email sent:', info.messageId);
    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error('Email send error:', error);
    return { success: false, error: error.message };
  }
}

// Send verification email
export async function sendVerificationEmail(email, name, code) {
  return sendEmail(email, 'verification', name, code);
}

// Send password reset email
export async function sendPasswordResetEmail(email, name, resetToken) {
  const resetLink = `https://client.jasperfinance.org/reset-password?token=${resetToken}`;
  return sendEmail(email, 'passwordReset', name, resetLink);
}

// Send welcome/approval email
export async function sendWelcomeEmail(email, name) {
  return sendEmail(email, 'welcomeApproved', name);
}

// Send admin notification for new registration
export async function sendAdminNotification(userName, userEmail, companyName) {
  const adminEmail = process.env.ADMIN_EMAIL || 'models@jasperfinance.org';
  return sendEmail(adminEmail, 'newRegistrationNotification', userName, userEmail, companyName);
}
