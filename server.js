// server.js
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const dns = require('node:dns');
const menu = require('./menu.json');

// Load env vars
dotenv.config();

// Force IPv4 DNS resolution
dns.setDefaultResultOrder('ipv4first');

// ENV
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const DATABASE_URL =
  process.env.DATABASE_URL ||
  'postgresql://postgres.fkxdolkyesmmxrtvblru:Catfish33!@aws-0-us-east-1.pooler.supabase.com:5432/postgres';

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL is not set in .env');
  process.exit(1);
}

// Postgres
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false },
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

// DB table setup
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

  await pool.query(`
    CREATE TABLE IF NOT EXISTS events (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      location TEXT,
      price NUMERIC,
      is_featured BOOLEAN DEFAULT false,
      start_at TIMESTAMP,
      end_at TIMESTAMP,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS videos (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      video_url TEXT NOT NULL,
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

// Middleware: require role
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

// AUTH — REGISTER (automatic admin by domain)
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

// AUTH — LOGIN
app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: 'missing_fields' });

  const result = await pool.query(`SELECT * FROM users WHERE email=$1`, [
    email.trim().toLowerCase(),
  ]);
  if (result.rows.length === 0)
    return res.status(401).json({ error: 'invalid_credentials' });

  const row = result.rows[0];
  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

  const user = { id: row.id, email: row.email, name: row.name, role: row.role };
  const token = signToken(user);
  res.json({ token, user });
});

// AUTH — CURRENT USER
app.get('/auth/me', authRequired, async (req, res) => {
  const result = await pool.query(
    `SELECT id, email, name, role FROM users WHERE id=$1`,
    [req.user.sub]
  );
  if (result.rows.length === 0)
    return res.status(404).json({ error: 'user_not_found' });
  res.json(result.rows[0]);
});

// ADMIN USERS
app.get('/admin/users', authRequired, requireRole('admin'), async (req, res) => {
  const result = await pool.query(
    `SELECT id, email, name, role, created_at FROM users ORDER BY created_at DESC`
  );
  res.json(result.rows);
});

// ADMIN VIDEOS — CREATE
app.post('/admin/videos', authRequired, requireRole('admin'), async (req, res) => {
  const { title, description, video_url } = req.body || {};
  if (!title || !video_url)
    return res.status(400).json({ error: 'missing_fields' });

  try {
    const result = await pool.query(
      `INSERT INTO videos (title, description, video_url)
       VALUES ($1, $2, $3) RETURNING *`,
      [title, description, video_url]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Video insert error:', err);
    res.status(500).json({ error: 'insert_failed' });
  }
});

// REWARDS
app.get('/rewards', (req, res) => {
  res.json({
    userId: 1,
    points: 230,
    tier: 'Silver',
    history: [
      { date: '2025-07-15', activity: 'Food Order', points: 20 },
      { date: '2025-07-08', activity: 'Tournament Win', points: 50 },
      { date: '2025-07-01', activity: 'Food Order', points: 10 },
    ],
  });
});

// MENU
app.get('/menu', (req, res) => {
  res.json(menu);
});

// EVENTS CRUD
app.get('/events', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM events ORDER BY start_at ASC`
  );
  res.json(rows);
});

app.post('/events', authRequired, requireRole('admin'), async (req, res) => {
  const {
    title,
    description,
    location,
    price,
    is_featured,
    start_at,
    end_at,
  } = req.body || {};
  if (!title) return res.status(400).json({ error: 'missing_title' });

  const result = await pool.query(
    `INSERT INTO events (title, description, location, price, is_featured, start_at, end_at)
     VALUES ($1,$2,$3,$4,$5,$6,$7)
     RETURNING *`,
    [title, description, location, price, is_featured, start_at, end_at]
  );

  res.status(201).json(result.rows[0]);
});

app.put('/events/:id', authRequired, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const {
    title,
    description,
    location,
    price,
    is_featured,
    start_at,
    end_at,
  } = req.body || {};

  const result = await pool.query(
    `UPDATE events
     SET title=$1, description=$2, location=$3, price=$4, is_featured=$5, start_at=$6, end_at=$7
     WHERE id=$8 RETURNING *`,
    [title, description, location, price, is_featured, start_at, end_at, id]
  );

  if (result.rows.length === 0)
    return res.status(404).json({ error: 'event_not_found' });
  res.json(result.rows[0]);
});

app.delete('/events/:id', authRequired, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  await pool.query(`DELETE FROM events WHERE id=$1`, [id]);
  res.json({ success: true });
});

// Start server
const PORT = process.env.PORT || 8080;
app.listen(PORT, async () => {
  await createTables();
  console.log(`🚀 Server running on port ${PORT}`);
});









