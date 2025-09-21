/**
 * Authentication Routes
 * Public routes for user registration, login, verification, and password reset
 */

const express = require('express');
const rateLimit = require('express-rate-limit');

const authController = require('../controllers/authController');

const router = express.Router();

/**
 * Rate limiting configurations for different endpoint types
 */

// Strict rate limiting for sensitive operations
const strictLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: {
    error: 'Too many attempts. Please try again in 15 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development'
});

// Moderate rate limiting for verification operations
const verificationLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 3, // 3 attempts per window
  message: {
    error: 'Too many verification attempts. Please try again in 5 minutes.'
  },
  standardHeaders: true,
  legacyHeaders: false,
  skip: (req) => process.env.NODE_ENV === 'development'
});

/**
 * Input validation middleware
 */
const validateEmailInput = (req, res, next) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({
      error: 'Email is required'
    });
  }
  
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({
      error: 'Please provide a valid email address'
    });
  }
  
  next();
};

/**
 * Authentication Routes
 */

/**
 * @route   POST /api/auth/signup
 * @desc    Register a new user account
 * @access  Public
 * @body    { email, password, name? }
 */
router.post('/signup', 
  strictLimiter,
  validateEmailInput,
  authController.signup
);

/**
 * @route   POST /api/auth/verify-email
 * @desc    Verify user email with verification code
 * @access  Public
 * @body    { email, code }
 */
router.post('/verify-email',
  verificationLimiter,
  validateEmailInput,
  authController.verifyEmail
);

/**
 * @route   POST /api/auth/signin
 * @desc    Sign in user and return JWT token
 * @access  Public
 * @body    { email, password }
 */
router.post('/signin',
  strictLimiter,
  validateEmailInput,
  authController.signin
);

/**
 * @route   POST /api/auth/resend-verification
 * @desc    Resend email verification code
 * @access  Public
 * @body    { email }
 */
router.post('/resend-verification',
  verificationLimiter,
  validateEmailInput,
  authController.resendVerification
);

/**
 * Password Reset Routes
 */

/**
 * @route   POST /api/auth/forgot-password
 * @desc    Send password reset code to user email
 * @access  Public
 * @body    { email }
 */
router.post('/forgot-password',
  strictLimiter,
  validateEmailInput,
  authController.forgotPassword
);

/**
 * @route   POST /api/auth/reset-password
 * @desc    Reset password using verification code
 * @access  Public
 * @body    { email, code, newPassword }
 */
router.post('/reset-password',
  strictLimiter,
  validateEmailInput,
  authController.resetPassword
);

/**
 * Session Management Routes
 */

/**
 * @route   POST /api/auth/logout
 * @desc    Logout user (client-side token removal)
 * @access  Public
 * @body    {}
 */
router.post('/logout', authController.logout);

/**
 * Development Only Routes
 * These routes should be disabled in production
 */

if (process.env.NODE_ENV !== 'production') {
  /**
   * @route   POST /api/auth/dev-verify-email
   * @desc    Force email verification (development only)
   * @access  Public (Development Only)
   * @body    { email }
   */
  router.post('/dev-verify-email',
    validateEmailInput,
    authController.devVerifyEmail
  );

  /**
   * @route   POST /api/auth/dev-reset-password
   * @desc    Force password reset (development only)
   * @access  Public (Development Only)
   * @body    { email, newPassword }
   */
  router.post('/dev-reset-password',
    validateEmailInput,
    authController.devResetPassword
  );
}

module.exports = router;
