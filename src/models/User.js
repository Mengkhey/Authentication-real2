// src/models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  name: { type: String },
  emailVerified: { type: Boolean, default: false },

  // For verification or reset codes we store hashedCode + expiry + type
  emailVerification: {
    codeHash: String,
    expiresAt: Date,
  },
  passwordReset: {
    codeHash: String,
    expiresAt: Date,
  },

  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('User', userSchema);
