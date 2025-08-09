const router = require('express').Router();
const fs = require('fs');
const bcrypt = require('bcryptjs');
const db = require('../services/db');
const { sign, authRequired } = require('../services/auth');

// Ensure tables exist on first import
db.exec(fs.readFileSync('db/schema.sql', 'utf8'));

router.post('/register', async (req, res) => {
  const { email, password, name } = req.body || {};
  if (!email || !password || !name) return res.status(400).json({ error: 'missing_fields' });

  const domain = (email || '').toLowerCase().split('@')[1] || '';
  const adminDomains = ['slatermediacompany.com', 'dozersgrill.com'];
  const role = adminDomains.includes(domain) ? 'admin' : 'customer';

  const hash = await bcrypt.hash(password, 10);
  try {
    const info = db.prepare(
      `INSERT INTO users (email, password_hash, name, role) VALUES (?, ?, ?, ?)`
    ).run(email.toLowerCase(), hash, name.trim(), role);

    // default settings
    db.prepare(`INSERT INTO user_settings (user_id) VALUES (?)`).run(info.lastInsertRowid);

    const user = db.prepare(`SELECT id, email, name, role FROM users WHERE id=?`)
      .get(info.lastInsertRowid);

    res.json({ token: sign(user), user });
  } catch (e) {
    if (String(e).includes('UNIQUE')) return res.status(409).json({ error: 'email_exists' });
    res.status(500).json({ error: 'register_failed' });
  }
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'missing_fields' });

  const row = db.prepare(`SELECT * FROM users WHERE email=?`).get(email.toLowerCase());
  if (!row) return res.status(401).json({ error: 'invalid_credentials' });

  const ok = await bcrypt.compare(password, row.password_hash);
  if (!ok) return res.status(401).json({ error: 'invalid_credentials' });

  const user = { id: row.id, email: row.email, name: row.name, role: row.role };
  res.json({ token: sign(user), user });
});

router.get('/me', authRequired, (req, res) => {
  const user = db.prepare(`SELECT id, email, name, role FROM users WHERE id=?`)
    .get(req.user.sub);
  if (!user) return res.status(404).json({ error: 'user_not_found' });
  res.json(user);
});

module.exports = router;
