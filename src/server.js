/**
 * Authentication API Server
 * Main server file for handling user authentication with JWT
 */

// Load environment variables
require('dotenv').config();

// Core dependencies
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

// Application modules
const { connectDB } = require('./config/db');
const { initMailer } = require('./config/mailer');
const { errorHandler } = require('./middleware/errorHandler');

// Route handlers
const authRoutes = require('./routes/auth');
const protectedRoutes = require('./routes/protected');

/**
 * Initialize Express application with middleware
 */
const app = express();

// Security middleware
app.use(helmet());

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));

// CORS configuration
app.use(cors({
  origin: ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Rate limiting for authentication routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  // In development we skip the global limiter to avoid blocking local testing.
  // In production keep a low limit to prevent abuse.
  max: process.env.NODE_ENV === 'development' ? 0 : 20, // 0 combined with `skip` means unlimited in dev
  message: {
    error: 'Too many authentication attempts, please try again later'
  },
  standardHeaders: true,
  legacyHeaders: false
  ,
  // Skip applying this global limiter when running in development
  skip: (req) => process.env.NODE_ENV === 'development'
});

// API routes
app.use('/api/auth', authLimiter, authRoutes);
app.use('/api', protectedRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.status(200).json({ 
    status: 'OK', 
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// 404 handler for unmatched routes
// Use app.all to avoid path parsing issues with the '*' pattern in some
// express/path-to-regexp versions.
// Generic 404 handler for unmatched routes
app.use((req, res) => {
  res.status(404).json({
    error: 'Route not found',
    path: req.originalUrl
  });
});

// Global error handling middleware (must be last)
app.use(errorHandler);

/**
 * Start the server
 */
const PORT = process.env.PORT || 4000;

const startServer = async () => {
  try {
    // Initialize mailer configuration
    await initMailer(process.env);
    
    // Connect to MongoDB
    await connectDB(process.env.MONGO_URI);
    
    // Start HTTP server
    app.listen(PORT, () => {
      console.log(`🚀 Server running on http://localhost:${PORT}`);
      console.log(`📊 Health check available at http://localhost:${PORT}/health`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error.message);
    process.exit(1);
  }
};

// Handle unhandled promise rejections
process.on('unhandledRejection', (err) => {
  console.error('🚨 Unhandled Promise Rejection:', err.message);
  process.exit(1);
});

// Handle uncaught exceptions
process.on('uncaughtException', (err) => {
  console.error('🚨 Uncaught Exception:', err.message);
  process.exit(1);
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('🛑 SIGINT received, shutting down gracefully');
  process.exit(0);
});

// Start the server
startServer();
