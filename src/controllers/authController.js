// src/controllers/authController.js
const User = require('../models/User');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { sendMail } = require('../config/mailer');

const CODE_LENGTH = Number(process.env.CODE_LENGTH) || 6;
const CODE_EXPIRES_MIN = Number(process.env.EMAIL_CODE_EXPIRES_MIN) || 15;

/* Helpers */
function generateNumericCode(len = CODE_LENGTH) {
  // generate numeric string, leading zeros allowed
  let code = '';
  for (let i = 0; i < len; i++) code += Math.floor(Math.random() * 10);
  return code;
}

function hashCode(code) {
  return crypto.createHash('sha256').update(code).digest('hex');
}

function addMinutes(d, minutes) {
  return new Date(d.getTime() + minutes * 60000);
}

async function sendVerificationEmail(userEmail, code) {
  const html = `<p>Your verification code is <b>${code}</b>. It expires in ${CODE_EXPIRES_MIN} minutes.</p>`;
  await sendMail({
    to: userEmail,
    from: process.env.EMAIL_FROM,
    subject: 'Verify your email',
    html,
    text: `Your verification code is ${code}. It expires in ${CODE_EXPIRES_MIN} minutes.`,
  });
}

async function sendResetEmail(userEmail, code) {
  const html = `<p>Your password reset code is <b>${code}</b>. It expires in ${CODE_EXPIRES_MIN} minutes.</p>`;
  await sendMail({
    to: userEmail,
    from: process.env.EMAIL_FROM,
    subject: 'Password reset code',
    html,
    text: `Your password reset code is ${code}. It expires in ${CODE_EXPIRES_MIN} minutes.`,
  });
}

/* Controllers */

exports.signup = async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const existing = await User.findOne({ email: email.toLowerCase() });
    if (existing) return res.status(400).json({ message: 'Email already registered' });

    const salt = await bcrypt.genSalt(10);
    const passwordHash = await bcrypt.hash(password, salt);

    const user = new User({
      email: email.toLowerCase(),
      passwordHash,
      name,
      emailVerified: false,
    });

    // generate verification code
    const code = generateNumericCode();
    user.emailVerification = {
      codeHash: hashCode(code),
      expiresAt: addMinutes(new Date(), CODE_EXPIRES_MIN),
    };

    await user.save();

    // Send email (async) - await so that client knows if send failed
    await sendVerificationEmail(user.email, code);

    return res.status(201).json({ message: 'User created. Verification code sent to email' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.verifyEmail = async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ message: 'Email and code required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ message: 'Invalid email or code' });

    if (!user.emailVerification?.codeHash || !user.emailVerification?.expiresAt) {
      return res.status(400).json({ message: 'No verification code found. Request a new one.' });
    }

    if (new Date() > new Date(user.emailVerification.expiresAt)) {
      return res.status(400).json({ message: 'Code expired. Request a new one.' });
    }

    if (hashCode(code) !== user.emailVerification.codeHash) {
      return res.status(400).json({ message: 'Incorrect code' });
    }

    user.emailVerified = true;
    user.emailVerification = undefined;
    await user.save();

    return res.json({ message: 'Email verified successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: 'Email and password required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ message: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.status(400).json({ message: 'Invalid credentials' });

    if (!user.emailVerified) return res.status(403).json({ message: 'Email not verified' });

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, {
      expiresIn: process.env.JWT_EXPIRES_IN || '7d',
    });

    return res.json({ token, user: { id: user._id, email: user.email, name: user.name } });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.resendVerification = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(400).json({ message: 'User not found' });
    if (user.emailVerified) return res.status(400).json({ message: 'Email already verified' });

    const code = generateNumericCode();
    user.emailVerification = {
      codeHash: hashCode(code),
      expiresAt: addMinutes(new Date(), CODE_EXPIRES_MIN),
    };
    await user.save();

    await sendVerificationEmail(user.email, code);
    return res.json({ message: 'Verification code resent' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ message: 'Email required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user) return res.status(200).json({ message: 'If an account exists, a reset code was sent' });
    // *Don't reveal whether user exists*

    const code = generateNumericCode();
    user.passwordReset = {
      codeHash: hashCode(code),
      expiresAt: addMinutes(new Date(), CODE_EXPIRES_MIN),
    };
    await user.save();

    await sendResetEmail(user.email, code);
    return res.status(200).json({ message: 'If an account exists, a reset code was sent' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.resetPassword = async (req, res) => {
  try {
    const { email, code, newPassword } = req.body;
    if (!email || !code || !newPassword) return res.status(400).json({ message: 'Email, code and new password required' });

    const user = await User.findOne({ email: email.toLowerCase() });
    if (!user || !user.passwordReset?.codeHash) return res.status(400).json({ message: 'Invalid request' });

    if (new Date() > new Date(user.passwordReset.expiresAt)) {
      return res.status(400).json({ message: 'Reset code expired' });
    }

    if (hashCode(code) !== user.passwordReset.codeHash) {
      return res.status(400).json({ message: 'Incorrect code' });
    }

    const salt = await bcrypt.genSalt(10);
    user.passwordHash = await bcrypt.hash(newPassword, salt);
    user.passwordReset = undefined;
    await user.save();

    return res.json({ message: 'Password updated. Please sign in with new password' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};

exports.logout = async (req, res) => {
  try {
    // For JWT-based authentication, logout is typically handled client-side
    // by removing the token from storage. However, we can acknowledge the logout.
    return res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ message: 'Server error' });
  }
};
