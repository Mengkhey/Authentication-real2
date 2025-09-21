/**
 * User Model
 * Mongoose schema for user authentication and profile data
 */

const mongoose = require('mongoose');

/**
 * Email verification schema
 */
const emailVerificationSchema = new mongoose.Schema({
  codeHash: {
    type: String,
    required: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 } // TTL index for automatic cleanup
  }
}, { _id: false });

/**
 * Password reset schema
 */
const passwordResetSchema = new mongoose.Schema({
  codeHash: {
    type: String,
    required: true
  },
  expiresAt: {
    type: Date,
    required: true,
    index: { expireAfterSeconds: 0 } // TTL index for automatic cleanup
  }
}, { _id: false });

/**
 * Main user schema
 */
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: [true, 'Email is required'],
    unique: true,
    lowercase: true,
    trim: true,
    match: [
      /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
      'Please provide a valid email address'
    ],
    index: true
  },
  
  passwordHash: {
    type: String,
    required: [true, 'Password is required'],
    select: false // Don't include password in queries by default
  },
  
  name: {
    type: String,
    trim: true,
    maxLength: [100, 'Name cannot exceed 100 characters']
  },
  
  emailVerified: {
    type: Boolean,
    default: false,
    index: true
  },
  
  emailVerification: {
    type: emailVerificationSchema,
    default: undefined
  },
  
  passwordReset: {
    type: passwordResetSchema,
    default: undefined
  },
  
  // Profile fields
  profile: {
    firstName: {
      type: String,
      trim: true,
      maxLength: [50, 'First name cannot exceed 50 characters']
    },
    lastName: {
      type: String,
      trim: true,
      maxLength: [50, 'Last name cannot exceed 50 characters']
    },
    avatar: {
      type: String,
      trim: true
    }
  },
  
  // Authentication metadata
  lastLogin: {
    type: Date,
    default: null
  },
  
  loginAttempts: {
    type: Number,
    default: 0
  },
  
  accountLocked: {
    type: Boolean,
    default: false
  },
  
  lockUntil: {
    type: Date,
    default: null
  },
  
  // Account status
  isActive: {
    type: Boolean,
    default: true,
    index: true
  },
  
  // Timestamps
  createdAt: {
    type: Date,
    default: Date.now,
    immutable: true
  },
  
  updatedAt: {
    type: Date,
    default: Date.now
  }
}, {
  timestamps: { 
    createdAt: 'createdAt', 
    updatedAt: 'updatedAt' 
  },
  versionKey: false
});

/**
 * Indexes for performance
 */
userSchema.index({ email: 1, emailVerified: 1 });
userSchema.index({ createdAt: -1 });
userSchema.index({ lastLogin: -1 });

/**
 * Virtual for full name
 */
userSchema.virtual('fullName').get(function() {
  if (this.profile?.firstName && this.profile?.lastName) {
    return `${this.profile.firstName} ${this.profile.lastName}`;
  }
  return this.name || '';
});

/**
 * Virtual for account lock status
 */
userSchema.virtual('isLocked').get(function() {
  return !!(this.accountLocked && this.lockUntil && this.lockUntil > Date.now());
});

/**
 * Pre-save middleware
 */
userSchema.pre('save', function(next) {
  // Update the updatedAt field
  this.updatedAt = new Date();
  
  // Clean up expired verification codes
  if (this.emailVerification?.expiresAt && this.emailVerification.expiresAt < new Date()) {
    this.emailVerification = undefined;
  }
  
  if (this.passwordReset?.expiresAt && this.passwordReset.expiresAt < new Date()) {
    this.passwordReset = undefined;
  }
  
  next();
});

/**
 * Instance methods
 */

/**
 * Check if account is locked
 * @returns {boolean} True if account is locked
 */
userSchema.methods.isAccountLocked = function() {
  return this.accountLocked && this.lockUntil && this.lockUntil > Date.now();
};

/**
 * Increment login attempts and lock account if necessary
 * @returns {Promise} Promise that resolves when operation is complete
 */
userSchema.methods.incrementLoginAttempts = function() {
  const maxAttempts = 5;
  const lockTime = 30 * 60 * 1000; // 30 minutes
  
  this.loginAttempts += 1;
  
  if (this.loginAttempts >= maxAttempts) {
    this.accountLocked = true;
    this.lockUntil = new Date(Date.now() + lockTime);
  }
  
  return this.save();
};

/**
 * Reset login attempts
 * @returns {Promise} Promise that resolves when operation is complete
 */
userSchema.methods.resetLoginAttempts = function() {
  this.loginAttempts = 0;
  this.accountLocked = false;
  this.lockUntil = null;
  this.lastLogin = new Date();
  
  return this.save();
};

/**
 * Get safe user object (without sensitive data)
 * @returns {Object} Safe user object
 */
userSchema.methods.toSafeObject = function() {
  return {
    id: this._id,
    email: this.email,
    name: this.name,
    fullName: this.fullName,
    emailVerified: this.emailVerified,
    profile: this.profile,
    lastLogin: this.lastLogin,
    isActive: this.isActive,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt
  };
};

/**
 * Static methods
 */

/**
 * Find user by email (case-insensitive)
 * @param {string} email - Email address
 * @returns {Promise} Promise that resolves to user document
 */
userSchema.statics.findByEmail = function(email) {
  return this.findOne({ 
    email: email.toLowerCase().trim(),
    isActive: true
  }).select('+passwordHash');
};

/**
 * Clean up expired verification codes
 * @returns {Promise} Promise that resolves when cleanup is complete
 */
userSchema.statics.cleanupExpiredCodes = function() {
  const now = new Date();
  
  return this.updateMany({
    $or: [
      { 'emailVerification.expiresAt': { $lt: now } },
      { 'passwordReset.expiresAt': { $lt: now } }
    ]
  }, {
    $unset: {
      emailVerification: 1,
      passwordReset: 1
    }
  });
};

/**
 * Transform function for JSON serialization
 */
userSchema.set('toJSON', {
  transform: function(doc, ret, options) {
    delete ret.passwordHash;
    delete ret.emailVerification;
    delete ret.passwordReset;
    delete ret.loginAttempts;
    delete ret.accountLocked;
    delete ret.lockUntil;
    return ret;
  },
  virtuals: true
});

module.exports = mongoose.model('User', userSchema);
