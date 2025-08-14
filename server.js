require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

const app = express();
app.use(cors());
app.use(helmet());
app.use(express.json());

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// JWT authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid token' });
    req.user = user;
    next();
  });
}

// Middleware to verify admin user
async function verifyAdmin(req, res, next) {
  try {
    const userId = req.user?.id;
    if (!userId) {
      return res.status(401).json({ error: 'Unauthorized: No user ID in token' });
    }

    const result = await pool.query(
      'SELECT * FROM admins WHERE user_id = $1 LIMIT 1',
      [userId]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'Forbidden: Not an admin' });
    }

    next();
  } catch (err) {
    console.error('Admin check failed:', err);
    res.status(500).json({ error: 'Server error' });
  }
}

// ===== VIDEOS ROUTES =====

// Get all videos
app.get('/videos', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM videos ORDER BY created_at DESC');
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching videos:', err);
    res.status(500).json({ error: 'Failed to fetch videos' });
  }
});

// Add a new video (Admins only)
app.post('/admin/videos', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { title, description, video_url } = req.body;

    if (!title || !video_url) {
      return res.status(400).json({ error: 'Title and video URL are required' });
    }

    const result = await pool.query(
      'INSERT INTO videos (title, description, video_url) VALUES ($1, $2, $3) RETURNING *',
      [title, description, video_url]
    );

    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error adding video:', err);
    res.status(500).json({ error: 'Failed to add video' });
  }
});

// Delete a video (Admins only)
app.delete('/admin/videos/:id', authenticateToken, verifyAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query('DELETE FROM videos WHERE id = $1', [id]);
    res.json({ success: true });
  } catch (err) {
    console.error('Error deleting video:', err);
    res.status(500).json({ error: 'Failed to delete video' });
  }
});

// ===== EVENTS ROUTES (already existing) =====
// ... keep your existing events routes here ...

// ===== START SERVER =====
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});













