/**
 * Email Configuration
 * SMTP transporter setup for sending emails
 */

const nodemailer = require('nodemailer');

let transporter = null;
let isInitialized = false;

/**
 * Email configuration validation
 * @param {Object} env - Environment variables
 * @throws {Error} If required configuration is missing
 */
const validateEmailConfig = (env) => {
  const requiredFields = ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASS', 'EMAIL_FROM'];
  const missingFields = requiredFields.filter(field => !env[field]);
  
  if (missingFields.length > 0) {
    throw new Error(`Missing required email configuration: ${missingFields.join(', ')}`);
  }
  
  // Validate email format for FROM address
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(env.EMAIL_FROM)) {
    throw new Error('EMAIL_FROM must be a valid email address');
  }
};

/**
 * Initialize email transporter
 * @param {Object} env - Environment variables
 * @returns {Promise} Promise that resolves when mailer is initialized
 */
const initMailer = async (env) => {
  try {
    // Validate configuration
    validateEmailConfig(env);
    
    const port = Number(env.SMTP_PORT) || 587;
    const isSecure = env.SMTP_SECURE === 'true' || port === 465;
    
    // Create transporter configuration
    const transporterConfig = {
      host: env.SMTP_HOST,
      port: port,
      secure: isSecure,
      auth: {
        user: env.SMTP_USER,
        pass: env.SMTP_PASS
      },
      // Additional security and reliability options
      connectionTimeout: 60000, // 1 minute
      greetingTimeout: 30000, // 30 seconds
      socketTimeout: 60000, // 1 minute
      pool: true, // Use connection pooling
      maxConnections: 5,
      maxMessages: 100,
      rateLimit: 14 // Max 14 messages per second
    };
    
    // Add TLS options for better security
    if (!isSecure) {
      transporterConfig.tls = {
        ciphers: 'SSLv3',
        rejectUnauthorized: false
      };
    }
    
  // Create transporter
  // nodemailer.createTransporter is not a function - correct method is createTransport
  transporter = nodemailer.createTransport(transporterConfig);
    
    // Verify connection
    await transporter.verify();
    
    isInitialized = true;
    console.log('📧 Email service initialized successfully');
    console.log(`📬 SMTP Host: ${env.SMTP_HOST}:${port}`);
    console.log(`📤 From Address: ${env.EMAIL_FROM}`);
    
  } catch (error) {
    console.error('❌ Failed to initialize email service:', error.message);
    
    // In production, email service is critical
    if (process.env.NODE_ENV === 'production') {
      throw new Error(`Email service initialization failed: ${error.message}`);
    }
    
    // In development, log warning but don't crash
    console.warn('⚠️  Email service not available in development mode');
  }
};

/**
 * Send email with comprehensive error handling
 * @param {Object} options - Email options
 * @param {string} options.to - Recipient email address
 * @param {string} options.subject - Email subject
 * @param {string} options.html - HTML content
 * @param {string} options.text - Plain text content
 * @param {string} options.from - Sender email (optional, uses default)
 * @returns {Promise} Promise that resolves with email info
 */
const sendMail = async ({ to, subject, html, text, from }) => {
  try {
    if (!transporter || !isInitialized) {
      throw new Error('Email service not initialized. Please check your SMTP configuration.');
    }
    
    // Input validation
    if (!to || !subject) {
      throw new Error('Recipient email and subject are required');
    }
    
    if (!html && !text) {
      throw new Error('Email content (HTML or text) is required');
    }
    
    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(to)) {
      throw new Error('Invalid recipient email address');
    }
    
    // Prepare email options
    const mailOptions = {
      from: from || process.env.EMAIL_FROM,
      to: to.toLowerCase().trim(),
      subject: subject.trim(),
      text: text || '',
      html: html || ''
    };
    
    // Send email
    const info = await transporter.sendMail(mailOptions);
    
    console.log(`📧 Email sent successfully to ${to}`);
    console.log(`📝 Message ID: ${info.messageId}`);
    
    return {
      success: true,
      messageId: info.messageId,
      response: info.response,
      envelope: info.envelope
    };
    
  } catch (error) {
    console.error('❌ Failed to send email:', error.message);
    
    // Re-throw with more context
    throw new Error(`Email delivery failed: ${error.message}`);
  }
};

/**
 * Test email connection
 * @returns {Promise} Promise that resolves with connection status
 */
const testConnection = async () => {
  try {
    if (!transporter) {
      return {
        success: false,
        message: 'Email service not initialized'
      };
    }
    
    await transporter.verify();
    
    return {
      success: true,
      message: 'Email service connection is healthy'
    };
    
  } catch (error) {
    return {
      success: false,
      message: `Email service connection failed: ${error.message}`
    };
  }
};

/**
 * Get email service status
 * @returns {Object} Service status information
 */
const getStatus = () => {
  return {
    initialized: isInitialized,
    connected: !!transporter,
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.SMTP_SECURE === 'true',
    fromAddress: process.env.EMAIL_FROM
  };
};

/**
 * Close email service connections
 * @returns {Promise} Promise that resolves when closed
 */
const closeConnections = async () => {
  try {
    if (transporter && transporter.close) {
      transporter.close();
      console.log('📧 Email service connections closed');
    }
    
    transporter = null;
    isInitialized = false;
    
  } catch (error) {
    console.error('Error closing email connections:', error);
  }
};

module.exports = {
  initMailer,
  sendMail,
  testConnection,
  getStatus,
  closeConnections,
  isInitialized: () => isInitialized
};
