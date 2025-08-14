import express from 'express';
import { Pool } from 'pg';

const router = express.Router();

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { require: true, rejectUnauthorized: false },
});

// GET all events
router.get('/', async (req, res) => {
  try {
    const result = await pool.query(`SELECT * FROM events ORDER BY start_at ASC`);
    res.json(result.rows);
  } catch (err) {
    console.error('Error fetching events:', err);
    res.status(500).json({ error: 'failed_to_fetch_events' });
  }
});

// GET featured event
router.get('/featured', async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM events WHERE is_featured = true ORDER BY start_at ASC LIMIT 1`
    );
    res.json(result.rows[0] || null);
  } catch (err) {
    console.error('Error fetching featured event:', err);
    res.status(500).json({ error: 'failed_to_fetch_featured' });
  }
});

// POST new event
router.post('/', async (req, res) => {
  const { title, description, location, price, is_featured, start_at, end_at } = req.body;
  try {
    const result = await pool.query(
      `INSERT INTO events (title, description, location, price, is_featured, start_at, end_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [title, description, location, price, is_featured, start_at, end_at]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating event:', err);
    res.status(500).json({ error: 'failed_to_create_event' });
  }
});

// PUT update event
router.put('/:id', async (req, res) => {
  const { id } = req.params;
  const { title, description, location, price, is_featured, start_at, end_at } = req.body;
  try {
    const result = await pool.query(
      `UPDATE events
       SET title=$1, description=$2, location=$3, price=$4, is_featured=$5, start_at=$6, end_at=$7
       WHERE id=$8
       RETURNING *`,
      [title, description, location, price, is_featured, start_at, end_at, id]
    );
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Error updating event:', err);
    res.status(500).json({ error: 'failed_to_update_event' });
  }
});

// POST feature an event
router.post('/feature', async (req, res) => {
  const { event_id } = req.body;
  if (!event_id) return res.status(400).json({ error: 'event_id_required' });

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`UPDATE events SET is_featured = false WHERE is_featured = true`);
    await client.query(`UPDATE events SET is_featured = true WHERE id = $1`, [event_id]);
    await client.query('COMMIT');
    res.json({ success: true });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('Error featuring event:', err);
    res.status(500).json({ error: 'failed_to_feature' });
  } finally {
    client.release();
  }
});

export default router;





