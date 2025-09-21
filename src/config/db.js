/**
 * Database Configuration
 * MongoDB connection setup with Mongoose
 */

const mongoose = require('mongoose');

/**
 * MongoDB connection options
 */
const mongooseOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  maxPoolSize: 10, // Maintain up to 10 socket connections
  serverSelectionTimeoutMS: 5000, // Keep trying to send operations for 5 seconds
  socketTimeoutMS: 45000, // Close sockets after 45 seconds of inactivity
  family: 4, // Use IPv4, skip trying IPv6
  retryWrites: true,
  retryReads: true
};

/**
 * Connect to MongoDB database
 * @param {string} mongoUri - MongoDB connection string
 * @returns {Promise} Promise that resolves when connected
 */
const connectDB = async (mongoUri) => {
  try {
    if (!mongoUri) {
      throw new Error('MongoDB connection string is required');
    }

    // Validate connection string format
    if (!mongoUri.startsWith('mongodb://') && !mongoUri.startsWith('mongodb+srv://')) {
      throw new Error('Invalid MongoDB connection string format');
    }

    // Set Mongoose options for better debugging in development
    if (process.env.NODE_ENV === 'development') {
      mongoose.set('debug', true);
    }

    // Connect to MongoDB
    const connection = await mongoose.connect(mongoUri, mongooseOptions);
    
    console.log(`📦 MongoDB connected successfully`);
    console.log(`🔗 Database: ${connection.connection.name}`);
    console.log(`🌐 Host: ${connection.connection.host}:${connection.connection.port}`);

    // Handle connection events
    mongoose.connection.on('error', (err) => {
      console.error('🚨 MongoDB connection error:', err);
    });

    mongoose.connection.on('disconnected', () => {
      console.warn('⚠️  MongoDB disconnected');
    });

    mongoose.connection.on('reconnected', () => {
      console.log('🔄 MongoDB reconnected');
    });

    // Handle application termination
    process.on('SIGINT', async () => {
      try {
        await mongoose.connection.close();
        console.log('🔌 MongoDB connection closed through app termination');
        process.exit(0);
      } catch (error) {
        console.error('Error closing MongoDB connection:', error);
        process.exit(1);
      }
    });

    return connection;

  } catch (error) {
    console.error('❌ Failed to connect to MongoDB:', error.message);
    
    // Exit process with failure in production
    if (process.env.NODE_ENV === 'production') {
      process.exit(1);
    }
    
    throw error;
  }
};

/**
 * Check database connection status
 * @returns {boolean} True if connected
 */
const isConnected = () => {
  return mongoose.connection.readyState === 1;
};

/**
 * Get connection status string
 * @returns {string} Connection status
 */
const getConnectionStatus = () => {
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting'
  };
  
  return states[mongoose.connection.readyState] || 'unknown';
};

/**
 * Disconnect from MongoDB
 * @returns {Promise} Promise that resolves when disconnected
 */
const disconnectDB = async () => {
  try {
    await mongoose.connection.close();
    console.log('🔌 MongoDB disconnected successfully');
  } catch (error) {
    console.error('❌ Error disconnecting from MongoDB:', error);
    throw error;
  }
};

/**
 * Health check for database connection
 * @returns {Object} Health check result
 */
const healthCheck = async () => {
  try {
    if (!isConnected()) {
      return {
        status: 'error',
        message: 'Database not connected',
        connected: false
      };
    }

    // Ping the database
    await mongoose.connection.db.admin().ping();
    
    return {
      status: 'ok',
      message: 'Database connection healthy',
      connected: true,
      database: mongoose.connection.name,
      host: mongoose.connection.host,
      port: mongoose.connection.port
    };
    
  } catch (error) {
    return {
      status: 'error',
      message: error.message,
      connected: false
    };
  }
};

module.exports = {
  connectDB,
  disconnectDB,
  isConnected,
  getConnectionStatus,
  healthCheck
};
