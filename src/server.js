// src/index.js
require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const connectDB = require('./config/db');
const { initMailer } = require('./config/mailer');

const authRoutes = require('./routes/auth');
const protectedRoutes = require('./routes/protected');

const app = express();

app.use(helmet());
app.use(express.json());
app.use(cors({
  origin: '*' // tighten in prod
}));

// Basic rate limit for auth routes
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: 'Too many attempts, try again later'
});

app.use('/api/auth', authLimiter);
app.use('/api/auth', authRoutes);
app.use('/api', protectedRoutes);

const PORT = process.env.PORT || 4500;

(async () => {
  try {
    initMailer(process.env);
    await connectDB(process.env.MONGO_URI);
    app.listen(PORT, () => {
      console.log(`Server running on port http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error(err);
    process.exit(1);
  }
})();
