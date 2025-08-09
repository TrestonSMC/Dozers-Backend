// Force IPv4 DNS resolution to avoid ENETUNREACH on some hosts
const dns = require('node:dns');
dns.setDefaultResultOrder('ipv4first');

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const menu = require('./menu.json');

// ENV variables
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const DATABASE_URL =
  process.env.DATABASE_URL ||
  'postgresql://postgres.fkxdolkyesmmxrtvblru:Catfish33!@aws-0-us-east-1.pooler.supabase.com:5432/postgres';

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL is not set in .env');
  process.exit(1);
}

// Postgres pool
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false } // required for Supabase
});

const app = express();
app.use(cors());
app.use(express.json());
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

// Helper: sign JWT
function signToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// Create DB tables if they don't exist
async function createTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'customer',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

// Middleware: require auth
function authRequired(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'missing_token' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

// Middleware: require specific role
function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role)
      return res.status(403).json({ error: 'forbidden' });
    next();
  };
}

// Routes
app.get('/', (req, res) => {
  res.send('API online');
});

// Register user
app.post('/auth/register', async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password || !name)
    return res.status(400).json({ error: 'missing_fields' });

  const domain = email.trim().toLowerCase().split('@')[1] || '';
  const adminDomains = ['slatermediacompany.com', 'dozersgrill.com'];
  const role = adminDomains.includes(domain) ? 'admin' : 'customer';

  const hash = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name, role)
       VALUES ($1, $2, $3, $4) RETURNING id, email, name, role`,
      [email.trim().toLowerCase(), hash, name.trim(), role]
    );
    const user = result.rows[0];
    const token = signToken(user);
    res.json({ token, user });
  } catch (e) {
    if (String(e).includes('duplicate key'))
      return res.status(409).json({ error: 'email_exists' });
    res.status(500).json({ error: 'register_failed' });
  }
});

// Login user
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'missing_fields' });

  const result = await pool.query(`SELECT * FROM users WHERE email=$1`, [email.trim().toLowerCase()]);
  if (result.rows.length === 0) return res.status(401).json({ error: 'invalid_credentials' });

  const row = result.rows[0];
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

  const user = { id: row.id, email: row.email, name: row.name, role: row.role };
  const token = signToken(user);
  res.json({ token, user });
});

// Get logged-in user info
app.get('/auth/me', authRequired, async (req, res) => {
  const result = await pool.query(
    `SELECT id, email, name, role FROM users WHERE id=$1`,
    [req.user.sub]
  );
  if (result.rows.length === 0) return res.status(404).json({ error: 'user_not_found' });
  res.json(result.rows[0]);
});

// Admin: list all users
app.get('/admin/users', authRequired, requireRole('admin'), async (req, res) => {
  const result = await pool.query(`SELECT id, email, name, role, created_at FROM users ORDER BY created_at DESC`);
  res.json(result.rows);
});

// Mock rewards
app.get('/rewards', (req, res) => {
  res.json({
    userId: 1,
    points: 230,
    tier: "Silver",
    history: [
      { date: "2025-07-15", activity: "Food Order", points: 20 },
      { date: "2025-07-08", activity: "Tournament Win", points: 50 },
      { date: "2025-07-01", activity: "Food Order", points: 10 }
    ]
  });
});

// Mock menu
app.get('/menu', (req, res) => {
  res.json(menu);
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, async () => {
  await createTables();
  console.log(`🚀 Server running on port ${PORT}`);
});






