// src/routes/auth.js
const express = require('express');
const router = express.Router();
const controller = require('../controllers/authController');

router.post('/signup', controller.signup);             // { email, password, name? }
router.post('/verify-email', controller.verifyEmail);  // { email, code }
router.post('/signin', controller.signin);             // { email, password }
router.post('/logout', controller.logout);             // { } - requires auth header
router.post('/resend-verification', controller.resendVerification); // { email }

router.post('/forgot-password', controller.forgotPassword); // { email }
router.post('/reset-password', controller.resetPassword);   // { email, code, newPassword }

module.exports = router;
