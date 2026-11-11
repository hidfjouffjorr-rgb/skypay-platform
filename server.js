const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname)));

// PostgreSQL Database Connection (Render Environment Variables ব্যবহৃত হবে)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Database Tables Initialization
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL
  )
`).then(() => console.log("Users table ready.")).catch(err => console.error(err));

pool.query(`
  CREATE TABLE IF NOT EXISTS admin_settings (
    id SERIAL PRIMARY KEY,
    setting_key VARCHAR(50) UNIQUE NOT NULL,
    setting_value TEXT NOT NULL
  )
`).then(() => console.log("Admin Settings table ready.")).catch(err => console.error(err));

// --- USER AUTHENTICATION APIs ---

// User Registration
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users (username, password) VALUES ($1, $2)', [username, hashedPassword]);
    res.json({ success: true, message: 'রেজিস্ট্রেশন সফল হয়েছে!' });
  } catch (err) {
    console.error(err);
    res.status(400).json({ success: false, message: 'এই নম্বর বা ইমেইল দিয়ে ইতিমধ্যে অ্যাকাউন্ট রয়েছে।' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'ব্যবহারকারী পাওয়া যায়নি।' });
    }
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ success: false, message: 'ভুল পাসওয়ার্ড!' });
    }
    res.json({ success: true, message: 'লগইন সফল হয়েছে!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'লগইন করতে সমস্যা হয়েছে।' });
  }
});

// --- SETTINGS APIS (Admin & User Sync) ---

// Get all settings (ইউজার ও এডমিন উভয়ের জন্য)
app.get('/api/settings', async (req, res) => {
  try {
    const result = await pool.query('SELECT setting_key, setting_value FROM admin_settings');
    const settings = {};
    result.rows.forEach(row => {
      settings[row.setting_key] = row.setting_value;
    });
    res.json({ success: true, settings });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'ডেটা লোড করতে সমস্যা হয়েছে।' });
  }
});

// Update settings (শুধুমাত্র এডমিন প্যানেল থেকে নিয়ন্ত্রিত)
app.post('/api/admin/update-settings', async (req, res) => {
  const { key, value } = req.body;
  try {
    await pool.query(`
      INSERT INTO admin_settings (setting_key, setting_value) 
      VALUES ($1, $2) 
      ON CONFLICT (setting_key) 
      DO UPDATE SET setting_value = $2
    `, [key, value]);
    
    res.json({ success: true, message: 'সফলভাবে আপডেট করা হয়েছে!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'আপডেট করতে সমস্যা হয়েছে।' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
