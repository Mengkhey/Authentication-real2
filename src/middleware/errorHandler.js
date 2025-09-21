/**
 * Global Error Handler Middleware
 * Centralized error handling for the authentication API
 */

/**
 * Custom error class for application errors
 */
class AppError extends Error {
  constructor(message, statusCode = 500) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Format validation errors
 * @param {Object} err - Mongoose validation error
 * @returns {Object} Formatted error object
 */
const handleValidationError = (err) => {
  const errors = Object.values(err.errors).map(error => {
    switch (error.kind) {
      case 'required':
        return `${error.path} is required`;
      case 'unique':
        return `${error.path} already exists`;
      case 'minlength':
        return `${error.path} must be at least ${error.properties.minlength} characters`;
      case 'maxlength':
        return `${error.path} cannot exceed ${error.properties.maxlength} characters`;
      default:
        return error.message;
    }
  });

  return {
    message: errors.join('. '),
    statusCode: 400
  };
};

/**
 * Format duplicate key errors
 * @param {Object} err - MongoDB duplicate key error
 * @returns {Object} Formatted error object
 */
const handleDuplicateKeyError = (err) => {
  const duplicateField = Object.keys(err.keyValue)[0];
  const fieldName = duplicateField === 'email' ? 'email address' : duplicateField;
  
  return {
    message: `An account with this ${fieldName} already exists`,
    statusCode: 409
  };
};

/**
 * Format MongoDB cast errors
 * @param {Object} err - MongoDB cast error
 * @returns {Object} Formatted error object
 */
const handleCastError = (err) => {
  return {
    message: `Invalid ${err.path}: ${err.value}`,
    statusCode: 400
  };
};

/**
 * Format JWT errors
 * @param {Object} err - JWT error
 * @returns {Object} Formatted error object
 */
const handleJWTError = (err) => {
  const jwtErrors = {
    'JsonWebTokenError': 'Invalid token. Please sign in again.',
    'TokenExpiredError': 'Your session has expired. Please sign in again.',
    'NotBeforeError': 'Token not active yet'
  };

  return {
    message: jwtErrors[err.name] || 'Authentication failed',
    statusCode: 401
  };
};

/**
 * Send error response in development
 * @param {Object} err - Error object
 * @param {Object} res - Express response object
 */
const sendErrorDev = (err, res) => {
  res.status(err.statusCode || 500).json({
    success: false,
    error: {
      message: err.message,
      stack: err.stack,
      name: err.name,
      statusCode: err.statusCode
    }
  });
};

/**
 * Send error response in production
 * @param {Object} err - Error object
 * @param {Object} res - Express response object
 */
const sendErrorProd = (err, res) => {
  // Only send operational errors to client
  if (err.isOperational) {
    res.status(err.statusCode).json({
      success: false,
      error: err.message
    });
  } else {
    // Log error for debugging
    console.error('Programming Error:', err);
    
    // Send generic message
    res.status(500).json({
      success: false,
      error: 'Something went wrong. Please try again later.'
    });
  }
};

/**
 * Main error handler middleware
 * @param {Error} err - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const errorHandler = (err, req, res, next) => {
  // Skip if response already sent
  if (res.headersSent) {
    return next(err);
  }

  let error = { ...err };
  error.message = err.message;
  error.statusCode = err.statusCode;

  // Log error details
  console.error('Error Details:', {
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });

  // Handle specific error types
  if (err.name === 'ValidationError') {
    const formattedError = handleValidationError(err);
    error.message = formattedError.message;
    error.statusCode = formattedError.statusCode;
    error.isOperational = true;
  }

  if (err.code === 11000) {
    const formattedError = handleDuplicateKeyError(err);
    error.message = formattedError.message;
    error.statusCode = formattedError.statusCode;
    error.isOperational = true;
  }

  if (err.name === 'CastError') {
    const formattedError = handleCastError(err);
    error.message = formattedError.message;
    error.statusCode = formattedError.statusCode;
    error.isOperational = true;
  }

  if (['JsonWebTokenError', 'TokenExpiredError', 'NotBeforeError'].includes(err.name)) {
    const formattedError = handleJWTError(err);
    error.message = formattedError.message;
    error.statusCode = formattedError.statusCode;
    error.isOperational = true;
  }

  // Handle rate limiting errors
  if (err.statusCode === 429) {
    error.message = 'Too many requests. Please try again later.';
    error.isOperational = true;
  }

  // Send appropriate error response
  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(error, res);
  } else {
    sendErrorProd(error, res);
  }
};

module.exports = {
  errorHandler,
  AppError
};