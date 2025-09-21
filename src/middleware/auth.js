/**
 * Authentication Middleware
 * Verifies JWT tokens and protects routes
 */

const jwt = require('jsonwebtoken');
const { AppError } = require('./errorHandler');

/**
 * Extract JWT token from request headers
 * @param {Object} req - Express request object
 * @returns {string|null} JWT token or null
 */
const extractToken = (req) => {
  const authHeader = req.headers.authorization;
  
  // Check Bearer token in Authorization header
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.split(' ')[1];
  }
  
  // Check token in cookies (if using cookie authentication)
  if (req.cookies && req.cookies.token) {
    return req.cookies.token;
  }
  
  return null;
};

/**
 * Verify JWT token and extract user information
 * @param {string} token - JWT token
 * @returns {Object} Decoded token payload
 * @throws {Error} If token is invalid or expired
 */
const verifyToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      throw new AppError('Your session has expired. Please sign in again.', 401);
    }
    if (error.name === 'JsonWebTokenError') {
      throw new AppError('Invalid authentication token. Please sign in again.', 401);
    }
    throw new AppError('Authentication failed. Please sign in again.', 401);
  }
};

/**
 * Main authentication middleware
 * Protects routes by verifying JWT tokens
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const authMiddleware = async (req, res, next) => {
  try {
    // Extract token from request
    const token = extractToken(req);
    
    if (!token) {
      return next(new AppError('Access denied. No authentication token provided.', 401));
    }

    // Verify token and extract payload
    const payload = verifyToken(token);
    
    if (!payload.id || !payload.email) {
      return next(new AppError('Invalid token payload. Please sign in again.', 401));
    }

    // Attach user information to request object
    req.user = {
      id: payload.id,
      email: payload.email
    };

    // Add token information for potential use in controllers
    req.token = token;
    req.tokenExp = payload.exp;

    next();

  } catch (error) {
    next(error);
  }
};

/**
 * Optional authentication middleware
 * Allows routes to be accessed with or without authentication
 * If authenticated, user info is attached to req.user
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const optionalAuth = async (req, res, next) => {
  try {
    const token = extractToken(req);
    
    if (token) {
      try {
        const payload = verifyToken(token);
        req.user = {
          id: payload.id,
          email: payload.email
        };
        req.token = token;
        req.tokenExp = payload.exp;
      } catch (error) {
        // For optional auth, we don't throw errors
        // Just continue without user info
        req.user = null;
      }
    } else {
      req.user = null;
    }

    next();

  } catch (error) {
    next(error);
  }
};

/**
 * Check if user has required permissions (placeholder for future role-based access)
 * @param {Array} requiredRoles - Required roles
 * @returns {Function} Middleware function
 */
const requireRoles = (requiredRoles = []) => {
  return (req, res, next) => {
    if (!req.user) {
      return next(new AppError('Authentication required', 401));
    }

    // Placeholder for role-based access control
    // In the future, you could check req.user.roles against requiredRoles
    
    next();
  };
};

module.exports = {
  authMiddleware,
  optionalAuth,
  requireRoles,
  extractToken,
  verifyToken
};
