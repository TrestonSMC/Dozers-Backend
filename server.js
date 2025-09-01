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
const { createClient } = require('@supabase/supabase-js');

dotenv.config();
dns.setDefaultResultOrder('ipv4first');

// ENV
const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const DATABASE_URL = process.env.DATABASE_URL;
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

if (!DATABASE_URL) {
  console.error('❌ DATABASE_URL is not set in .env');
  process.exit(1);
}

// Postgres
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false },
});

// Supabase client (kept for your other features)
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

const app = express();
app.use(cors());
app.use(express.json());
app.use(helmet());
app.use(rateLimit({ windowMs: 60_000, max: 120 }));

// JWT helper
function signToken(user) {
  return jwt.sign(
    { sub: user.id, role: user.role, name: user.name, email: user.email },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

// ----------------- DB TABLES -----------------
async function createTables() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      name TEXT NOT NULL,
      phone TEXT,
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

  // Videos table with position (order field)
  await pool.query(`
    CREATE TABLE IF NOT EXISTS videos (
      id UUID DEFAULT gen_random_uuid() PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      video_url TEXT NOT NULL,
      position INT NOT NULL DEFAULT 0,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // In case the table existed before without position, add it safely
  await pool.query(`
    ALTER TABLE IF EXISTS videos
    ADD COLUMN IF NOT EXISTS position INT NOT NULL DEFAULT 0;
  `);

  // Index for fast ordering
  await pool.query(`
    CREATE INDEX IF NOT EXISTS idx_videos_position ON videos(position);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notification_preferences (
      user_id INT REFERENCES users(id) PRIMARY KEY,
      push_enabled BOOLEAN DEFAULT true,
      email_enabled BOOLEAN DEFAULT false
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS rewards (
      user_id INT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      points INT DEFAULT 0,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS reward_history (
      id SERIAL PRIMARY KEY,
      user_id INT REFERENCES users(id) ON DELETE CASCADE,
      activity TEXT NOT NULL,
      points INT NOT NULL,
      date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      audience TEXT DEFAULT 'all',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

// ----------------- MIDDLEWARE -----------------
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

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user || req.user.role !== role)
      return res.status(403).json({ error: 'forbidden' });
    next();
  };
}

// ----------------- ROUTES -----------------
app.get('/', (req, res) => res.send('API online'));

// ---------- AUTH ----------
app.post('/auth/register', async (req, res) => {
  const { email, password, name, phone } = req.body || {};
  if (!email || !password || !name || !phone)
    return res.status(400).json({ error: 'missing_fields' });

  const domain = email.trim().toLowerCase().split('@')[1] || '';
  const adminDomains = ['slatermediacompany.com', 'dozersgrill.com'];
  const role = adminDomains.includes(domain) ? 'admin' : 'customer';

  const hash = await bcrypt.hash(password, 10);
  try {
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, name, phone, role)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id, email, name, phone, role`,
      [email.trim().toLowerCase(), hash, name.trim(), phone.trim(), role]
    );
    const user = result.rows[0];

    await pool.query(
      `INSERT INTO rewards (user_id, points) VALUES ($1, 0)
       ON CONFLICT DO NOTHING`,
      [user.id]
    );

    const token = signToken(user);
    res.json({ token, user });
  } catch (e) {
    if (String(e).includes('duplicate key'))
      return res.status(409).json({ error: 'email_exists' });
    res.status(500).json({ error: 'register_failed' });
  }
});

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

  const user = {
    id: row.id,
    email: row.email,
    name: row.name,
    phone: row.phone,
    role: row.role,
  };
  const token = signToken(user);
  res.json({ token, user });
});

app.get('/auth/me', authRequired, async (req, res) => {
  const result = await pool.query(
    `SELECT id, email, name, phone, role FROM users WHERE id=$1`,
    [req.user.sub]
  );
  if (result.rows.length === 0)
    return res.status(404).json({ error: 'user_not_found' });
  res.json(result.rows[0]);
});

// ---------- ADMIN ----------
app.get('/admin/users', authRequired, requireRole('admin'), async (req, res) => {
  const result = await pool.query(
    `SELECT id, email, name, phone, role, created_at FROM users ORDER BY created_at DESC`
  );
  res.json(result.rows);
});

app.delete('/admin/users/:id', authRequired, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    if (Number(id) === req.user.sub) {
      return res.status(400).json({ error: 'cannot_delete_self' });
    }
    const result = await pool.query(
      `DELETE FROM users WHERE id=$1 RETURNING id, email, name, phone, role`,
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'user_not_found' });
    }
    res.json({ success: true, message: `User ${result.rows[0].email} deleted` });
  } catch (err) {
    console.error('Delete user error:', err);
    res.status(500).json({ error: 'delete_failed' });
  }
});

// ---------- NOTIFICATIONS ----------
app.post('/admin/notifications', authRequired, requireRole('admin'), async (req, res) => {
  const { title, body, audience = 'all' } = req.body || {};
  if (!title || !body) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO notifications (title, body, audience)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [title, body, audience]
    );

    res.json({ success: true, notification: result.rows[0] });
  } catch (err) {
    console.error('Create notification error:', err);
    res.status(500).json({ error: 'create_failed' });
  }
});

app.get('/notifications', authRequired, async (req, res) => {
  try {
    const { rows } = await pool.query(
      `SELECT * FROM notifications ORDER BY created_at DESC LIMIT 50`
    );
    res.json(rows);
  } catch (err) {
    console.error('Fetch notifications error:', err);
    res.status(500).json({ error: 'fetch_failed' });
  }
});

app.delete('/admin/notifications/:id', authRequired, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(
      `DELETE FROM notifications WHERE id=$1 RETURNING *`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'notification_not_found' });
    }

    res.json({ success: true });
  } catch (err) {
    console.error('Delete notification error:', err);
    res.status(500).json({ error: 'delete_failed' });
  }
});

// ---------- MENU ----------
app.get('/menu', (req, res) => res.json(menu));

// ---------- REWARDS ----------
app.post('/checkout', authRequired, async (req, res) => {
  const { items = [], total = 0 } = req.body;
  const userId = req.user.sub;

  const pointsEarned = Math.round(total);
  try {
    await pool.query(`
      INSERT INTO rewards (user_id, points)
      VALUES ($1, $2)
      ON CONFLICT (user_id) DO UPDATE
      SET points = rewards.points + EXCLUDED.points,
          updated_at = CURRENT_TIMESTAMP
    `, [userId, pointsEarned]);

    await pool.query(
      `INSERT INTO reward_history (user_id, activity, points)
       VALUES ($1, $2, $3)`,
      [userId, "Food Purchase", pointsEarned]
    );

    const { rows } = await pool.query(
      `SELECT points FROM rewards WHERE user_id=$1`,
      [userId]
    );

    res.json({
      success: true,
      message: 'Checkout successful',
      pointsEarned,
      newBalance: rows[0].points
    });
  } catch (err) {
    console.error('Checkout error:', err);
    res.status(500).json({ error: 'checkout_failed' });
  }
});

app.get('/rewards/:userId', authRequired, async (req, res) => {
  const { userId } = req.params;
  try {
    if (req.user.role !== 'admin' && req.user.sub !== Number(userId)) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const { rows } = await pool.query(
      `SELECT points FROM rewards WHERE user_id=$1`,
      [userId]
    );
    res.json({ userId, points: rows.length > 0 ? rows[0].points : 0 });
  } catch (err) {
    console.error('Get rewards error:', err);
    res.status(500).json({ error: 'fetch_failed' });
  }
});

app.get('/rewards/:userId/history', authRequired, async (req, res) => {
  const { userId } = req.params;
  try {
    if (req.user.role !== 'admin' && req.user.sub !== Number(userId)) {
      return res.status(403).json({ error: 'forbidden' });
    }

    const { rows: historyRows } = await pool.query(
      `SELECT activity, points, date
       FROM reward_history
       WHERE user_id=$1
       ORDER BY date DESC`,
      [userId]
    );

    const { rows: rewardRows } = await pool.query(
      `SELECT points FROM rewards WHERE user_id=$1`,
      [userId]
    );

    res.json({
      userId,
      points: rewardRows.length > 0 ? rewardRows[0].points : 0,
      history: historyRows
    });
  } catch (err) {
    console.error('Get history error:', err);
    res.status(500).json({ error: 'fetch_failed' });
  }
});

// ---------- EVENTS ----------
app.get('/events', async (req, res) => {
  const { rows } = await pool.query(`SELECT * FROM events ORDER BY start_at ASC`);
  res.json(rows);
});

app.post('/events', authRequired, requireRole('admin'), async (req, res) => {
  const { title, description, location, price, is_featured, start_at, end_at } = req.body || {};
  if (!title) return res.status(400).json({ error: 'missing_title' });

  try {
    if (is_featured) {
      await pool.query(`UPDATE events SET is_featured=false`);
    }

    const result = await pool.query(
      `INSERT INTO events (title, description, location, price, is_featured, start_at, end_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [title, description, location, price, is_featured, start_at, end_at]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Create event error:', err);
    res.status(500).json({ error: 'create_failed' });
  }
});

app.put('/events/:id', authRequired, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  const { title, description, location, price, is_featured, start_at, end_at } = req.body || {};

  try {
    if (is_featured) {
      await pool.query(`UPDATE events SET is_featured=false`);
    }

    const result = await pool.query(
      `UPDATE events
       SET title=$1, description=$2, location=$3, price=$4, is_featured=$5, start_at=$6, end_at=$7
       WHERE id=$8 RETURNING *`,
      [title, description, location, price, is_featured, start_at, end_at, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'event_not_found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error('Update event error:', err);
    res.status(500).json({ error: 'update_failed' });
  }
});

app.delete('/events/:id', authRequired, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    await pool.query(`DELETE FROM events WHERE id=$1`, [id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Delete event error:', err);
    res.status(500).json({ error: 'delete_failed' });
  }
});

// ---------- VIDEOS ----------
app.get('/videos', async (req, res) => {
  const { rows } = await pool.query(
    `SELECT * FROM videos ORDER BY position ASC, created_at DESC`
  );
  res.json(rows);
});

app.post('/admin/videos', authRequired, requireRole('admin'), async (req, res) => {
  const { title, description, video_url } = req.body || {};
  if (!title || !video_url) {
    return res.status(400).json({ error: 'missing_fields' });
  }

  try {
    const result = await pool.query(
      `INSERT INTO videos (title, description, video_url, position)
       VALUES ($1, $2, $3, COALESCE((SELECT MAX(position)+1 FROM videos), 0))
       RETURNING *`,
      [title, description, video_url]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Create video error:', err);
    res.status(500).json({ error: 'create_failed' });
  }
});

app.delete('/admin/videos/:id', authRequired, requireRole('admin'), async (req, res) => {
  const { id } = req.params;
  try {
    const result = await pool.query(`DELETE FROM videos WHERE id=$1 RETURNING *`, [id]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'video_not_found' });
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Delete video error:', err);
    res.status(500).json({ error: 'delete_failed' });
  }
});

app.put('/admin/videos/reorder', authRequired, requireRole('admin'), async (req, res) => {
  const { videos } = req.body || {};
  if (!Array.isArray(videos)) {
    return res.status(400).json({ error: 'invalid_payload' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const v of videos) {
      await client.query(`UPDATE videos SET position=$1 WHERE id=$2`, [v.position, v.id]);
    }
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Reorder videos error:', err);
    res.status(500).json({ error: 'reorder_failed' });
  } finally {
    client.release();
  }
});

// ----------------- START -----------------
const PORT = process.env.PORT || 8080;
app.listen(PORT, async () => {
  await createTables();
  console.log(`🚀 Server running on port ${PORT}`);
});


























