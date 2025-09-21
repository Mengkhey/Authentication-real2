// src/config/mailer.js
const nodemailer = require('nodemailer');

let transporter = null;

function initMailer(env) {
  transporter = nodemailer.createTransport({
    host: env.SMTP_HOST,
    port: Number(env.SMTP_PORT || 587),
    secure: env.SMTP_SECURE === 'true' || env.SMTP_PORT == 465,
    auth: {
      user: env.SMTP_USER,
      pass: env.SMTP_PASS,
    },
  });
}

async function sendMail({ to, subject, html, text, from }) {
  if (!transporter) throw new Error('Mailer not initialized');
  const info = await transporter.sendMail({
    from,
    to,
    subject,
    text,
    html,
  });
  return info;
}

module.exports = { initMailer, sendMail };
