/**
 * Protected Routes
 * Routes that require authentication
 */

const express = require('express');
const User = require('../models/User');
const { authMiddleware } = require('../middleware/auth');
const { AppError } = require('../middleware/errorHandler');

const router = express.Router();

/**
 * User Profile Routes
 */

/**
 * @route   GET /api/me
 * @desc    Get current user profile
 * @access  Private
 */
router.get('/me', authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return next(new AppError('User not found', 404));
    }

    if (!user.isActive) {
      return next(new AppError('Account has been deactivated', 403));
    }

    res.json({
      success: true,
      user: user.toSafeObject()
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   PUT /api/me
 * @desc    Update current user profile
 * @access  Private
 * @body    { name?, profile?: { firstName?, lastName?, avatar? } }
 */
router.put('/me', authMiddleware, async (req, res, next) => {
  try {
    const { name, profile } = req.body;
    
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return next(new AppError('User not found', 404));
    }

    if (!user.isActive) {
      return next(new AppError('Account has been deactivated', 403));
    }

    // Update allowed fields
    if (name !== undefined) {
      user.name = name?.trim() || null;
    }

    if (profile) {
      user.profile = {
        ...user.profile,
        firstName: profile.firstName?.trim() || user.profile?.firstName,
        lastName: profile.lastName?.trim() || user.profile?.lastName,
        avatar: profile.avatar?.trim() || user.profile?.avatar
      };
    }

    await user.save();

    res.json({
      success: true,
      message: 'Profile updated successfully',
      user: user.toSafeObject()
    });

  } catch (error) {
    next(error);
  }
});

/**
 * @route   DELETE /api/me
 * @desc    Deactivate user account (soft delete)
 * @access  Private
 */
router.delete('/me', authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return next(new AppError('User not found', 404));
    }

    // Soft delete by deactivating account
    user.isActive = false;
    await user.save();

    res.json({
      success: true,
      message: 'Account has been deactivated successfully'
    });

  } catch (error) {
    next(error);
  }
});

/**
 * Account Information Routes
 */

/**
 * @route   GET /api/account/stats
 * @desc    Get account statistics and info
 * @access  Private
 */
router.get('/account/stats', authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.id);
    
    if (!user) {
      return next(new AppError('User not found', 404));
    }

    const stats = {
      accountAge: user.createdAt,
      lastLogin: user.lastLogin,
      emailVerified: user.emailVerified,
      profileCompleteness: calculateProfileCompleteness(user),
      accountStatus: user.isActive ? 'active' : 'inactive'
    };

    res.json({
      success: true,
      stats
    });

  } catch (error) {
    next(error);
  }
});

/**
 * System Health Routes
 */

/**
 * @route   GET /api/health/detailed
 * @desc    Get detailed system health (authenticated)
 * @access  Private
 */
router.get('/health/detailed', authMiddleware, async (req, res, next) => {
  try {
    const { healthCheck } = require('../config/db');
    const { getStatus: getEmailStatus } = require('../config/mailer');
    
    const dbHealth = await healthCheck();
    const emailStatus = getEmailStatus();

    res.json({
      success: true,
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      user: {
        id: req.user.id,
        email: req.user.email
      },
      services: {
        database: dbHealth,
        email: emailStatus
      },
      memory: process.memoryUsage(),
      environment: process.env.NODE_ENV
    });

  } catch (error) {
    next(error);
  }
});

/**
 * Utility Functions
 */

/**
 * Calculate profile completeness percentage
 * @param {Object} user - User document
 * @returns {number} Completeness percentage
 */
const calculateProfileCompleteness = (user) => {
  const fields = [
    user.name,
    user.profile?.firstName,
    user.profile?.lastName,
    user.emailVerified
  ];
  
  const completedFields = fields.filter(field => !!field).length;
  return Math.round((completedFields / fields.length) * 100);
};

module.exports = router;
