const express = require('express');
const { Pool } = require('pg');
const path = require('path');
const bcrypt = require('bcrypt'); // পাসওয়ার্ড সিকিউর করার জন্য

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

// PostgreSQL Database Connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Database Table Creation
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    mobile VARCHAR(20) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`).then(() => {
  console.log("Database connected & 'users' table ready.");
}).catch(err => console.error("Database connection error:", err));

// --- API ROUTES ---

// 1. User Registration Route
app.post('/api/register', async (req, res) => {
  const { mobile, password } = req.body;
  try {
    // চেক করা ইউজার আগে থেকেই আছে কিনা
    const userCheck = await pool.query('SELECT * FROM users WHERE mobile = $1', [mobile]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ success: false, message: 'این নম্বর দিয়ে ইতিমধ্যে অ্যাকাউন্ট খোলা হয়েছে!' });
    }

    // পাসওয়ার্ড হ্যাশ করা
    const hashedPassword = await bcrypt.hash(password, 10);

    // নতুন ইউজার ডাটাবেসে সংরক্ষণ করা
    await pool.query('INSERT INTO users (mobile, password) VALUES ($1, $2)', [mobile, hashedPassword]);
    res.json({ success: true, message: 'সফলভাবে রেজিস্ট্রেশন সম্পন্ন হয়েছে!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'সার্ভারে সমস্যা হয়েছে।' });
  }
});

// 2. User Login Route
app.post('/api/login', async (req, res) => {
  const { mobile, password } = req.body;
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE mobile = $1', [mobile]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ success: false, message: 'ভুল নম্বর অথবা অ্যাকাউন্ট পাওয়া যায়নি।' });
    }

    const user = userResult.rows[0];
    const isMatch = await bcrypt.compare(password, user.password);
    
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'পাসওয়ার্ড সঠিক নয়।' });
    }

    res.json({ success: true, message: 'লগইন সফল হয়েছে!', role: user.role });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: 'সার্ভারে সমস্যা হয়েছে।' });
  }
});

// Home Route
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Server Start
app.listen(port, () => {
  console.log(`SKYPAY Server is running on port ${port}`);
});
