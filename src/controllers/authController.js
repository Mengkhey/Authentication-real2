/**
 * Authentication Controller
 * Handles user registration, login, email verification, and password reset
 */

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const User = require('../models/User');
const { sendMail } = require('../config/mailer');

// Configuration constants
const CONFIG = {
  CODE_LENGTH: Number(process.env.CODE_LENGTH) || 6,
  CODE_EXPIRES_MIN: Number(process.env.EMAIL_CODE_EXPIRES_MIN) || 15,
  BCRYPT_SALT_ROUNDS: 12,
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '7d'
};

/**
 * Utility Functions
 */

/**
 * Generate a numeric verification code
 * @param {number} length - Length of the code
 * @returns {string} Numeric code
 */
const generateNumericCode = (length = CONFIG.CODE_LENGTH) => {
  let code = '';
  for (let i = 0; i < length; i++) {
    code += Math.floor(Math.random() * 10);
  }
  return code;
};

/**
 * Hash a verification code using SHA-256
 * @param {string} code - Code to hash
 * @returns {string} Hashed code
 */
const hashCode = (code) => {
  return crypto.createHash('sha256').update(code).digest('hex');
};

/**
 * Add minutes to a date
 * @param {Date} date - Base date
 * @param {number} minutes - Minutes to add
 * @returns {Date} New date with added minutes
 */
const addMinutes = (date, minutes) => {
  return new Date(date.getTime() + minutes * 60000);
};

/**
 * Validate email format
 * @param {string} email - Email to validate
 * @returns {boolean} True if valid email
 */
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * Validate password strength
 * @param {string} password - Password to validate
 * @returns {object} Validation result with isValid flag and message
 */
const validatePassword = (password) => {
  if (!password || password.length < 8) {
    return { isValid: false, message: 'Password must be at least 8 characters long' };
  }
  
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  if (!hasUpperCase || !hasLowerCase || !hasNumbers || !hasSpecialChar) {
    return {
      isValid: false,
      message: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    };
  }
  
  return { isValid: true };
};

/**
 * Email Service Functions
 */

/**
 * Send verification email
 * @param {string} userEmail - Recipient email
 * @param {string} code - Verification code
 */
const sendVerificationEmail = async (userEmail, code) => {
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2>Email Verification</h2>
      <p>Thank you for registering! Please use the following verification code to complete your registration:</p>
      <div style="background-color: #f5f5f5; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 2px; margin: 20px 0;">
        ${code}
      </div>
      <p><strong>This code will expire in ${CONFIG.CODE_EXPIRES_MIN} minutes.</strong></p>
      <p>If you didn't request this verification, please ignore this email.</p>
    </div>
  `;
  
  await sendMail({
    to: userEmail,
    from: process.env.EMAIL_FROM,
    subject: 'Verify your email address',
    html,
    text: `Your verification code is ${code}. It expires in ${CONFIG.CODE_EXPIRES_MIN} minutes.`
  });
};

/**
 * Send password reset email
 * @param {string} userEmail - Recipient email
 * @param {string} code - Reset code
 */
const sendResetEmail = async (userEmail, code) => {
  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2>Password Reset Request</h2>
      <p>You have requested to reset your password. Please use the following code:</p>
      <div style="background-color: #f5f5f5; padding: 20px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 2px; margin: 20px 0;">
        ${code}
      </div>
      <p><strong>This code will expire in ${CONFIG.CODE_EXPIRES_MIN} minutes.</strong></p>
      <p>If you didn't request this password reset, please ignore this email and your password will remain unchanged.</p>
    </div>
  `;
  
  await sendMail({
    to: userEmail,
    from: process.env.EMAIL_FROM,
    subject: 'Password Reset Code',
    html,
    text: `Your password reset code is ${code}. It expires in ${CONFIG.CODE_EXPIRES_MIN} minutes.`
  });
};

/**
 * Controller Functions
 */

/**
 * User Registration
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.signup = async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Input validation
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password are required' 
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        error: 'Please provide a valid email address' 
      });
    }

    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: passwordValidation.message 
      });
    }

    // Check if user already exists
    const normalizedEmail = email.toLowerCase().trim();
    const existingUser = await User.findOne({ email: normalizedEmail });
    
    if (existingUser) {
      return res.status(409).json({ 
        error: 'An account with this email already exists' 
      });
    }

    // Hash password
    const salt = await bcrypt.genSalt(CONFIG.BCRYPT_SALT_ROUNDS);
    const passwordHash = await bcrypt.hash(password, salt);

    // Generate verification code
    const verificationCode = generateNumericCode();
    const codeHash = hashCode(verificationCode);
    const expiresAt = addMinutes(new Date(), CONFIG.CODE_EXPIRES_MIN);

    // Create user
    const user = new User({
      email: normalizedEmail,
      passwordHash,
      name: name?.trim() || null,
      emailVerified: false,
      emailVerification: {
        codeHash,
        expiresAt
      }
    });

    await user.save();

    // Send verification email. If email fails in development, return the code in response
    try {
      await sendVerificationEmail(normalizedEmail, verificationCode);
      res.status(201).json({ 
        message: 'Account created successfully. Please check your email for verification code.' 
      });
    } catch (mailError) {
      console.error('Email send error during signup:', mailError.message || mailError);
      // In development, include the verification code in the response to allow testing
      if (process.env.NODE_ENV !== 'production') {
        return res.status(201).json({
          message: 'Account created successfully (email delivery failed in development).',
          devVerificationCode: verificationCode
        });
      }

      // In production, treat as an error
      return res.status(500).json({
        error: 'Account created but failed to send verification email. Please contact support.'
      });
    }

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      error: 'Failed to create account. Please try again.' 
    });
  }
};

/**
 * Email Verification
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.verifyEmail = async (req, res) => {
  try {
    const { email, code } = req.body;

    // Input validation
    if (!email || !code) {
      return res.status(400).json({ 
        error: 'Email and verification code are required' 
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        error: 'Please provide a valid email address' 
      });
    }

    // Find user
  const normalizedEmail = email.toLowerCase().trim();
  // Ensure passwordHash is selected so we can compare the password
  const user = await User.findOne({ email: normalizedEmail }).select('+passwordHash');
    
    if (!user) {
      return res.status(400).json({ 
        error: 'Invalid email or verification code' 
      });
    }

    // Check if email is already verified
    if (user.emailVerified) {
      return res.status(400).json({ 
        error: 'Email is already verified' 
      });
    }

    // Check if verification code exists
    if (!user.emailVerification?.codeHash || !user.emailVerification?.expiresAt) {
      return res.status(400).json({ 
        error: 'No verification code found. Please request a new one.' 
      });
    }

    // Check if code has expired
    if (new Date() > new Date(user.emailVerification.expiresAt)) {
      return res.status(400).json({ 
        error: 'Verification code has expired. Please request a new one.' 
      });
    }

    // Verify code
    const codeHash = hashCode(code.trim());
    if (codeHash !== user.emailVerification.codeHash) {
      return res.status(400).json({ 
        error: 'Invalid verification code' 
      });
    }

    // Update user
    user.emailVerified = true;
    user.emailVerification = undefined;
    await user.save();

    res.json({ 
      message: 'Email verified successfully! You can now sign in.' 
    });

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ 
      error: 'Failed to verify email. Please try again.' 
    });
  }
};

/**
 * User Sign In
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.signin = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Input validation
    if (!email || !password) {
      return res.status(400).json({ 
        error: 'Email and password are required' 
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        error: 'Please provide a valid email address' 
      });
    }

    // Find user
  const normalizedEmail = email.toLowerCase().trim();
  // include the passwordHash (select explicitly) so bcrypt.compare can read it
  const user = await User.findOne({ email: normalizedEmail }).select('+passwordHash');
    
    if (!user) {
      return res.status(401).json({ 
        error: 'Invalid email or password' 
      });
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.passwordHash);
    if (!isPasswordValid) {
      return res.status(401).json({ 
        error: 'Invalid email or password' 
      });
    }

    // Check email verification
    if (!user.emailVerified) {
      return res.status(403).json({ 
        error: 'Please verify your email before signing in' 
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { 
        id: user._id, 
        email: user.email 
      }, 
      process.env.JWT_SECRET, 
      { 
        expiresIn: CONFIG.JWT_EXPIRES_IN 
      }
    );

    // Update last login
    user.lastLogin = new Date();
    await user.save();

    res.json({
      message: 'Signed in successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        emailVerified: user.emailVerified
      }
    });

  } catch (error) {
    console.error('Sign in error:', error);
    res.status(500).json({ 
      error: 'Failed to sign in. Please try again.' 
    });
  }
};

/**
 * Resend Verification Code
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.resendVerification = async (req, res) => {
  try {
    const { email } = req.body;

    // Input validation
    if (!email) {
      return res.status(400).json({ 
        error: 'Email is required' 
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        error: 'Please provide a valid email address' 
      });
    }

    // Find user
    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    
    if (!user) {
      return res.status(404).json({ 
        error: 'No account found with this email address' 
      });
    }

    // Check if already verified
    if (user.emailVerified) {
      return res.status(400).json({ 
        error: 'Email is already verified' 
      });
    }

    // Generate new verification code
    const verificationCode = generateNumericCode();
    const codeHash = hashCode(verificationCode);
    const expiresAt = addMinutes(new Date(), CONFIG.CODE_EXPIRES_MIN);

    // Update user
    user.emailVerification = {
      codeHash,
      expiresAt
    };
    await user.save();

    // Send verification email
    await sendVerificationEmail(normalizedEmail, verificationCode);

    res.json({ 
      message: 'Verification code sent to your email' 
    });

  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ 
      error: 'Failed to resend verification code. Please try again.' 
    });
  }
};

/**
 * Forgot Password - Send Reset Code
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    // Input validation
    if (!email) {
      return res.status(400).json({ 
        error: 'Email is required' 
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        error: 'Please provide a valid email address' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });

    // Always return success message for security (don't reveal if user exists)
    const successMessage = 'If an account with this email exists, a password reset code has been sent.';

    if (!user) {
      return res.status(200).json({ message: successMessage });
    }

    // Generate reset code
    const resetCode = generateNumericCode();
    const codeHash = hashCode(resetCode);
    const expiresAt = addMinutes(new Date(), CONFIG.CODE_EXPIRES_MIN);

    // Update user with reset code
    user.passwordReset = {
      codeHash,
      expiresAt
    };
    await user.save();

    // Send reset email
    await sendResetEmail(normalizedEmail, resetCode);

    // Log for development (remove in production)
    if (process.env.NODE_ENV !== 'production') {
      console.log(`🔑 Password reset code for ${normalizedEmail}: ${resetCode}`);
    }

    res.status(200).json({ message: successMessage });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      error: 'Failed to process password reset request. Please try again.' 
    });
  }
};

/**
 * Reset Password with Code
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.resetPassword = async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;

    // Input validation
    if (!email || !code || !newPassword) {
      return res.status(400).json({ 
        error: 'Email, reset code, and new password are required' 
      });
    }

    if (!isValidEmail(email)) {
      return res.status(400).json({ 
        error: 'Please provide a valid email address' 
      });
    }

    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: passwordValidation.message 
      });
    }

    // Find user
    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    
    if (!user || !user.passwordReset?.codeHash) {
      return res.status(400).json({ 
        error: 'Invalid reset request' 
      });
    }

    // Check if code has expired
    if (new Date() > new Date(user.passwordReset.expiresAt)) {
      return res.status(400).json({ 
        error: 'Reset code has expired. Please request a new one.' 
      });
    }

    // Verify reset code
    const codeHash = hashCode(code.trim());
    if (codeHash !== user.passwordReset.codeHash) {
      return res.status(400).json({ 
        error: 'Invalid reset code' 
      });
    }

    // Hash new password
    const salt = await bcrypt.genSalt(CONFIG.BCRYPT_SALT_ROUNDS);
    const newPasswordHash = await bcrypt.hash(newPassword, salt);

    // Update user
    user.passwordHash = newPasswordHash;
    user.passwordReset = undefined;
    await user.save();

    res.json({ 
      message: 'Password has been reset successfully. Please sign in with your new password.' 
    });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ 
      error: 'Failed to reset password. Please try again.' 
    });
  }
};

/**
 * Logout User
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.logout = async (req, res) => {
  try {
    // For JWT-based authentication, logout is handled client-side
    // by removing the token from storage. Server acknowledges the logout.
    res.json({ 
      message: 'Logged out successfully' 
    });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ 
      error: 'Failed to logout. Please try again.' 
    });
  }
};

/**
 * Development Only Functions
 * These should be removed or disabled in production
 */

/**
 * DEV: Force Email Verification (Development Only)
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.devVerifyEmail = async (req, res) => {
  // Only allow in development environment
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Endpoint not found' });
  }

  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ 
        error: 'Email is required' 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found' 
      });
    }

    user.emailVerified = true;
    user.emailVerification = undefined;
    await user.save();

    res.json({ 
      message: 'Email verified successfully (development mode)' 
    });

  } catch (error) {
    console.error('Dev verify email error:', error);
    res.status(500).json({ 
      error: 'Failed to verify email' 
    });
  }
};

/**
 * DEV: Force Password Reset (Development Only)
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 */
exports.devResetPassword = async (req, res) => {
  // Only allow in development environment
  if (process.env.NODE_ENV === 'production') {
    return res.status(404).json({ error: 'Endpoint not found' });
  }

  try {
    const { email, newPassword } = req.body;

    if (!email || !newPassword) {
      return res.status(400).json({ 
        error: 'Email and new password are required' 
      });
    }

    const passwordValidation = validatePassword(newPassword);
    if (!passwordValidation.isValid) {
      return res.status(400).json({ 
        error: passwordValidation.message 
      });
    }

    const normalizedEmail = email.toLowerCase().trim();
    const user = await User.findOne({ email: normalizedEmail });
    
    if (!user) {
      return res.status(404).json({ 
        error: 'User not found' 
      });
    }

    const salt = await bcrypt.genSalt(CONFIG.BCRYPT_SALT_ROUNDS);
    user.passwordHash = await bcrypt.hash(newPassword, salt);
    await user.save();

    res.json({ 
      message: 'Password updated successfully (development mode)' 
    });

  } catch (error) {
    console.error('Dev reset password error:', error);
    res.status(500).json({ 
      error: 'Failed to reset password' 
    });
  }
};
