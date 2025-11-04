const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const dotenv = require('dotenv');
const fetch = require('node-fetch');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

app.use(helmet());
app.use(cors());
app.use(bodyParser.json({ limit: '5mb' }));

// Basic rate limiter
const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 200 });
app.use(limiter);

// Simple firewall: optional environment variables ALLOWED_IPS (comma list) or BLOCKED_IPS
const allowedIps = process.env.ALLOWED_IPS ? process.env.ALLOWED_IPS.split(',').map(s => s.trim()) : null;
const blockedIps = process.env.BLOCKED_IPS ? process.env.BLOCKED_IPS.split(',').map(s => s.trim()) : [];

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  if (blockedIps.includes(ip)) return res.status(403).json({ error: 'forbidden' });
  if (allowedIps && allowedIps.length && !allowedIps.includes(ip)) return res.status(403).json({ error: 'forbidden' });
  next();
});

// Phone validation per region
const phoneValidators = {
  NG: /^((\+?234)|0)?[789][01]\d{8}$/,
  KE: /^(?:\+?254|0)?7\d{8}$/,
  ZA: /^(?:\+?27|0)6\d{8}$/,
  IN: /^(?:\+?91|0)?[6-9]\d{9}$/,
  AE: /^(?:\+?971|0)?5\d{8}$/,
  SA: /^(?:\+?966|0)?5\d{8}$/
};

// Database (SQLite) - simple file
const db = new sqlite3.Database(process.env.DB_FILE || './data.db');

// Initialize tables
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    passwordHash TEXT,
    isAdmin INTEGER DEFAULT 0,
    twoFactorRequested INTEGER DEFAULT 0,
    twoFactorEnabled INTEGER DEFAULT 0,
    twoFactorOTP TEXT,
    twoFactorOTPExpires INTEGER,
    createdAt TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS orders (
    id TEXT PRIMARY KEY,
    data TEXT,
    date TEXT
  )`);
});

const ADMIN_ACCESS_CODE = process.env.ADMIN_ACCESS_CODE || 'admin123';

// Utility: verify reCAPTCHA token with Google (optional)
async function verifyRecaptcha(token) {
  const secret = process.env.RECAPTCHA_SECRET;
  if (!secret) return { success: true, note: 'no secret configured' };
  try {
    const resp = await fetch('https://www.google.com/recaptcha/api/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `secret=${encodeURIComponent(secret)}&response=${encodeURIComponent(token)}`
    });
    return await resp.json();
  } catch (err) {
    return { success: false, error: 'recaptcha verification failed' };
  }
}

// Auth: register
app.post('/api/auth/register', async (req, res) => {
  const { email, password, recaptchaToken } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  // verify recaptcha if provided
  if (recaptchaToken) {
    const v = await verifyRecaptcha(recaptchaToken);
    if (!v.success) return res.status(400).json({ error: 'recaptcha failed' });
  }

  const pwHash = bcrypt.hashSync(password, 10);
  const createdAt = new Date().toISOString();
  db.run('INSERT INTO users (email, passwordHash, createdAt) VALUES (?,?,?)', [email, pwHash, createdAt], function(err) {
    if (err) {
      return res.status(409).json({ error: 'user exists' });
    }
    res.json({ ok: true });
  });
});

// Auth: login (if twoFactorEnabled, server will issue a transient OTP)
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'missing' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = bcrypt.compareSync(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });

    if (user.twoFactorEnabled) {
      // create ephemeral OTP and store expiry
      const otp = Math.floor(100000 + Math.random() * 900000).toString();
      const expires = Date.now() + 5 * 60 * 1000; // 5 minutes
      db.run('UPDATE users SET twoFactorOTP = ?, twoFactorOTPExpires = ? WHERE id = ?', [otp, expires, user.id]);
      // For demo purposes: return OTP in response only if DEV_SHOW_OTP env var is set
      if (process.env.DEV_SHOW_OTP === 'true') {
        return res.json({ twoFactorRequired: true, otp });
      }
      return res.json({ twoFactorRequired: true });
    }

    res.json({ email: user.email });
  });
});

// Verify OTP
app.post('/api/auth/verify-otp', (req, res) => {
  const { email, otp } = req.body;
  if (!email || !otp) return res.status(400).json({ error: 'missing' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'invalid' });
    if (!user.twoFactorOTP || !user.twoFactorOTPExpires) return res.status(400).json({ error: 'no otp' });
    if (Date.now() > user.twoFactorOTPExpires) return res.status(400).json({ error: 'otp expired' });
    if (user.twoFactorOTP !== otp) return res.status(400).json({ error: 'invalid otp' });
    // clear otp
    db.run('UPDATE users SET twoFactorOTP = NULL, twoFactorOTPExpires = NULL WHERE id = ?', [user.id]);
    return res.json({ email: user.email });
  });
});

// Request 2FA (user requests admin approval to enable two-factor auth)
app.post('/api/auth/request-2fa', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'missing' });
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = bcrypt.compareSync(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    db.run('UPDATE users SET twoFactorRequested = 1 WHERE id = ?', [user.id], function(err) {
      if (err) return res.status(500).json({ error: 'db error' });
      return res.json({ ok: true, message: 'Two-factor requested. An administrator must approve.' });
    });
  });
});

// Create order (store JSON in orders table)
app.post('/api/orders', (req, res) => {
  const { items, region, fullName, address, city, zipCode, paymentMethod, phone, userEmail } = req.body;
  if (!items || !items.length) return res.status(400).json({ error: 'no items' });
  // phone validation
  if (phone && phoneValidators[region]) {
    const re = phoneValidators[region];
    if (!re.test(phone)) return res.status(400).json({ error: 'invalid phone format for region ' + region });
  }

  const orderId = 'ORD' + Math.random().toString(36).substr(2, 9).toUpperCase();
  const order = {
    id: orderId,
    items,
    status: 'pending_payment',
    region,
    fullName,
    address,
    city,
    zipCode,
    paymentMethod,
    phone,
    userEmail: userEmail || null,
    date: new Date().toISOString(),
    tracking: {
      steps: [
        { name: 'Order Placed', completed: true, date: new Date().toISOString() },
        { name: 'Processing', completed: false },
        { name: 'Shipped', completed: false },
        { name: 'Out for Delivery', completed: false },
        { name: 'Delivered', completed: false }
      ]
    }
  };
  db.run('INSERT INTO orders (id, data, date) VALUES (?,?,?)', [orderId, JSON.stringify(order), order.date], function(err) {
    if (err) return res.status(500).json({ error: 'db error' });
    return res.json({ orderId });
  });
});

// Get orders for user or all
app.get('/api/orders', (req, res) => {
  const { email } = req.query;
  if (email) {
    db.all('SELECT * FROM orders', [], (err, rows) => {
      if (err) return res.status(500).json({ error: 'db error' });
      const userOrders = rows.map(r => JSON.parse(r.data)).filter(o => o.userEmail === email);
      return res.json(userOrders);
    });
  } else {
    db.all('SELECT * FROM orders', [], (err, rows) => {
      if (err) return res.status(500).json({ error: 'db error' });
      return res.json(rows.map(r => JSON.parse(r.data)));
    });
  }
});

// Get single order
app.get('/api/orders/:id', (req, res) => {
  db.get('SELECT * FROM orders WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'not found' });
    return res.json(JSON.parse(row.data));
  });
});

// Admin: list all orders (requires x-admin-code header matching ADMIN_ACCESS_CODE)
app.get('/api/admin/orders', (req, res) => {
  const code = req.header('x-admin-code');
  if (code !== ADMIN_ACCESS_CODE) return res.status(403).json({ error: 'forbidden' });
  db.all('SELECT * FROM orders', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    return res.json(rows.map(r => JSON.parse(r.data)));
  });
});

// Admin: list pending 2FA requests
app.get('/api/admin/pending-2fa', (req, res) => {
  const code = req.header('x-admin-code');
  if (code !== ADMIN_ACCESS_CODE) return res.status(403).json({ error: 'forbidden' });
  db.all('SELECT id,email,createdAt FROM users WHERE twoFactorRequested = 1', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    return res.json(rows);
  });
});

// Admin: approve 2FA for a user
app.post('/api/admin/approve-2fa', (req, res) => {
  const code = req.header('x-admin-code');
  if (code !== ADMIN_ACCESS_CODE) return res.status(403).json({ error: 'forbidden' });
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });
  db.run('UPDATE users SET twoFactorRequested = 0, twoFactorEnabled = 1 WHERE email = ?', [email], function(err) {
    if (err) return res.status(500).json({ error: 'db error' });
    return res.json({ ok: true });
  });
});

// Admin: update tracking step
app.put('/api/orders/:id/tracking', (req, res) => {
  const code = req.header('x-admin-code');
  if (code !== ADMIN_ACCESS_CODE) return res.status(403).json({ error: 'forbidden' });
  const { stepIndex, completed } = req.body;
  if (typeof stepIndex !== 'number') return res.status(400).json({ error: 'stepIndex required' });
  db.get('SELECT * FROM orders WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'not found' });
    const order = JSON.parse(row.data);
    if (!order.tracking || !order.tracking.steps[stepIndex]) return res.status(400).json({ error: 'invalid step' });
    order.tracking.steps[stepIndex].completed = !!completed;
    order.tracking.steps[stepIndex].date = completed ? new Date().toISOString() : null;
    db.run('UPDATE orders SET data = ? WHERE id = ?', [JSON.stringify(order), order.id], function(err) {
      if (err) return res.status(500).json({ error: 'db error' });
      return res.json({ ok: true, order });
    });
  });
});

// Simulate STK push (for demo)
app.post('/api/payments/stk', (req, res) => {
  const { phone, amount, orderId } = req.body;
  db.get('SELECT * FROM orders WHERE id = ?', [orderId], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'order not found' });
    const order = JSON.parse(row.data);
    // simulate async confirmation after 3 seconds
    setTimeout(() => {
      order.status = 'paid';
      order.tracking.steps[1].completed = true;
      order.tracking.steps[1].date = new Date().toISOString();
      db.run('UPDATE orders SET data = ? WHERE id = ?', [JSON.stringify(order), order.id]);
      console.log(`Order ${orderId} marked paid by simulated STK push`);
    }, 3000);
    return res.json({ ok: true, message: 'STK push initiated (simulated)' });
  });
});

app.listen(PORT, () => console.log('Server running on port', PORT));
