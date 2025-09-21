// src/routes/protected.js
const express = require('express');
const router = express.Router();
const auth = require('../middleware/auth');

router.get('/me', auth, async (req, res) => {
  // req.user set by middleware
  res.json({ message: 'This is protected', user: req.user });
});

module.exports = router;
