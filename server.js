const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;

const requiredEnv = [
  "DATABASE_URL",
  "JWT_SECRET",
  "ADMIN_EMAIL",
  "ADMIN_PASSWORD_HASH",
  "GEMINI_API_KEY"
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`Missing required environment variable: ${key}`);
    process.exit(1);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.static(path.join(__dirname)));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 15
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

function makeToken(payload) {
  return jwt.sign(payload, process.env.JWT_SECRET, {
    expiresIn: "7d"
  });
}

function userAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "user" || !decoded.id) {
      throw new Error("Invalid role");
    }

    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({
      error: "Please log in again."
    });
  }
}

function adminAuth(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.startsWith("Bearer ")
      ? header.slice(7)
      : "";

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== "admin") {
      throw new Error("Invalid role");
    }

    next();
  } catch {
    res.status(401).json({
      error: "Admin login required."
    });
  }
}

function normalizePhone(value) {
  return String(value || "").replace(/[\s\-()]/g, "");
}

function validAmount(value) {
  return Number.isFinite(Number(value)) && Number(value) > 0;
}

function validAmountOrZero(value) {
  return Number.isFinite(Number(value)) && Number(value) >= 0;
}

// TELEGRAM NOTIFICATION
async function sendTelegramMessage(message) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;
  const chatId = process.env.TELEGRAM_CHAT_ID;

  if (!botToken || !chatId) {
    console.error("Telegram configuration is missing.");
    return false;
  }

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${botToken}/sendMessage`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          chat_id: chatId,
          text: message
        })
      }
    );

    const result = await response.json();

    if (!response.ok || !result.ok) {
      console.error("Telegram error:", result);
      return false;
    }

    return true;
  } catch (error) {
    console.error("Telegram notification failed:", error.message);
    return false;
  }
}

// DATABASE INITIALIZATION
async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      uid VARCHAR(30) UNIQUE NOT NULL,
      username VARCHAR(100),
      name VARCHAR(100) NOT NULL,
      phone VARCHAR(30),
      password_hash TEXT NOT NULL,
      referral_code VARCHAR(30) UNIQUE NOT NULL,
      referred_by INTEGER REFERENCES users(id),
      balance NUMERIC(14,2) NOT NULL DEFAULT 0,
      total_deposit NUMERIC(14,2) NOT NULL DEFAULT 0,
      total_withdraw NUMERIC(14,2) NOT NULL DEFAULT 0,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE users ADD COLUMN IF NOT EXISTS username VARCHAR(100);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS phone VARCHAR(30);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS uid VARCHAR(30);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(100);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code VARCHAR(30);
    ALTER TABLE users ADD COLUMN IF NOT EXISTS referred_by INTEGER;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS balance NUMERIC(14,2) NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS total_deposit NUMERIC(14,2) NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS total_withdraw NUMERIC(14,2) NOT NULL DEFAULT 0;
    ALTER TABLE users ADD COLUMN IF NOT EXISTS status VARCHAR(20) NOT NULL DEFAULT 'active';
    ALTER TABLE users ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT NOW();

    ALTER TABLE users ALTER COLUMN username DROP NOT NULL;

    DO $$
    BEGIN
      IF EXISTS (
        SELECT 1
        FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'users'
          AND column_name = 'password'
      ) THEN
        ALTER TABLE users ALTER COLUMN password DROP NOT NULL;
      END IF;
    END $$;

    CREATE UNIQUE INDEX IF NOT EXISTS users_phone_unique
      ON users(phone) WHERE phone IS NOT NULL;
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id SERIAL PRIMARY KEY,
      name VARCHAR(120) NOT NULL,
      price NUMERIC(14,2) NOT NULL DEFAULT 0,
      duration_days INTEGER NOT NULL DEFAULT 1,
      daily_estimate NUMERIC(14,2) NOT NULL DEFAULT 0,
      image_url TEXT DEFAULT '',
      description TEXT DEFAULT '',
      active BOOLEAN NOT NULL DEFAULT TRUE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      type VARCHAR(20) NOT NULL,
      method VARCHAR(20) NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      sender_number VARCHAR(40) DEFAULT '',
      account_number VARCHAR(40) DEFAULT '',
      transaction_id VARCHAR(120) DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      reviewed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS plans (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      product_id INTEGER REFERENCES products(id) ON DELETE SET NULL,
      product_name VARCHAR(120) NOT NULL,
      price NUMERIC(14,2) NOT NULL,
      daily_estimate NUMERIC(14,2) NOT NULL DEFAULT 0,
      duration_days INTEGER NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_messages (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role VARCHAR(20) NOT NULL,
      content TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS chat_messages_user_created_idx
    ON chat_messages(user_id, created_at);
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_escalations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      reason TEXT DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const products = await pool.query("SELECT COUNT(*) FROM products");

  if (Number(products.rows[0].count) === 0) {
    const names = [
      "Starter Service",
      "Basic Service",
      "Silver Service",
      "Gold Service",
      "Premium Service",
      "Digital Pack 01",
      "Digital Pack 02",
      "Digital Pack 03",
      "Digital Pack 04",
      "Digital Pack 05",
      "Digital Pack 06",
      "Digital Pack 07",
      "Digital Pack 08",
      "Digital Pack 09",
      "Digital Pack 10"
    ];

    for (const name of names) {
      await pool.query(
        `INSERT INTO products
         (name, price, duration_days, daily_estimate, description)
         VALUES ($1, 0, 1, 0, $2)`,
        [name, "Please ask the administrator for product details."]
      );
    }
  }

  console.log("SKYPAY database ready.");
}// HEALTH CHECK
app.get("/api/health", (req, res) => {
  res.json({ status: "ok", app: "SKYPAY" });
});

// REGISTRATION
app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");
    const referralCode = String(req.body.referralCode || "").trim();

    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({ error: "Enter a valid name." });
    }

    if (!/^\+?[0-9]{8,16}$/.test(phone)) {
      return res.status(400).json({ error: "Enter a valid phone number." });
    }

    if (password.length < 6 || password.length > 100) {
      return res.status(400).json({ error: "Password must be at least 6 characters." });
    }

    const duplicate = await pool.query(
      "SELECT id FROM users WHERE phone=$1", [phone]
    );

    if (duplicate.rows.length) {
      return res.status(409).json({ error: "This phone number is already registered." });
    }

    let referrer = null;

    if (referralCode) {
      const found = await pool.query(
        "SELECT id FROM users WHERE referral_code=$1", [referralCode]
      );
      if (found.rows.length) referrer = found.rows[0].id;
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const uid = "SKY" + Date.now().toString().slice(-8) +
      Math.floor(Math.random() * 90 + 10);
    const code = "SKY" + Math.random().toString(36).slice(2, 9).toUpperCase();

    const result = await pool.query(
      `INSERT INTO users
       (uid,username,name,phone,password_hash,referral_code,referred_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id,uid,username,name,phone,referral_code,balance,status`,
      [uid, phone, name, phone, passwordHash, code, referrer]
    );

    const user = result.rows[0];
    const token = makeToken({ id: user.id, role: "user" });

    res.status(201).json({
      message: "Registration successful.",
      token,
      user
    });
  } catch (error) {
    console.error("Registration:", error);
    if (error.code === "23505") {
      return res.status(409).json({ error: "This phone number or account is already registered." });
    }
    res.status(500).json({ error: "Registration failed. Please try again." });
  }
});

// USER LOGIN
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE phone=$1", [phone]
    );
    const user = result.rows[0];

    if (!user || !user.password_hash ||
        !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "Incorrect phone number or password." });
    }

    if (user.status !== "active") {
      return res.status(403).json({ error: "This account is not active." });
    }

    const token = makeToken({ id: user.id, role: "user" });
    delete user.password_hash;
    delete user.password;

    res.json({ message: "Login successful.", token, user });
  } catch (error) {
    console.error("Login:", error);
    res.status(500).json({ error: "Login failed." });
  }
});

// PUBLIC PRODUCTS
app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,name,price,duration_days,daily_estimate,image_url,description
       FROM products WHERE active=TRUE ORDER BY id`
    );
    res.json({ products: result.rows });
  } catch (error) {
    console.error("Products:", error);
    res.status(500).json({ error: "Could not load products." });
  }
});

// USER PROFILE
app.get("/api/me", userAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT u.id,u.uid,u.username,u.name,u.phone,u.referral_code,
       u.balance,u.total_deposit,u.total_withdraw,u.status,
       (SELECT COUNT(*) FROM plans p
        WHERE p.user_id=u.id AND p.status='active') AS active_plans
       FROM users u WHERE u.id=$1`,
      [req.userId]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({ user: result.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Could not load profile." });
  }
});

// DEPOSIT REQUEST
app.post("/api/deposit", userAuth, async (req, res) => {
  try {
    const method = String(req.body.method || "").toLowerCase();
    const amount = Number(req.body.amount);
    const sender = normalizePhone(req.body.senderNumber);
    const transactionId = String(req.body.transactionId || "").trim();

    if (!["bkash", "nagad"].includes(method)) {
      return res.status(400).json({ error: "Choose bKash or Nagad." });
    }
    if (!validAmount(amount) || amount > 1000000) {
      return res.status(400).json({ error: "Enter a valid amount." });
    }
    if (!/^\+?[0-9]{8,16}$/.test(sender)) {
      return res.status(400).json({ error: "Enter a valid sender number." });
    }
    if (transactionId.length < 4 || transactionId.length > 120) {
      return res.status(400).json({ error: "Enter a valid transaction ID." });
    }

    await pool.query(
      `INSERT INTO payment_requests
       (user_id,type,method,amount,sender_number,transaction_id)
       VALUES ($1,'deposit',$2,$3,$4,$5)`,
      [req.userId, method, amount, sender, transactionId]
    );

    res.status(201).json({
      message: "Deposit request submitted for admin review."
    });
  } catch (error) {
    console.error("Deposit:", error);
    res.status(500).json({ error: "Could not submit deposit request." });
  }
});

// WITHDRAWAL REQUEST
app.post("/api/withdraw", userAuth, async (req, res) => {
  const client = await pool.connect();
  let started = false;

  try {
    const method = String(req.body.method || "").toLowerCase();
    const amount = Number(req.body.amount);
    const account = normalizePhone(req.body.accountNumber);

    if (!["bkash", "nagad"].includes(method)) {
      return res.status(400).json({ error: "Choose bKash or Nagad." });
    }
    if (!validAmount(amount) || amount > 1000000) {
      return res.status(400).json({ error: "Enter a valid amount." });
    }
    if (!/^\+?[0-9]{8,16}$/.test(account)) {
      return res.status(400).json({ error: "Enter a valid account number." });
    }

    await client.query("BEGIN");
    started = true;

    const user = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE", [req.userId]
    );

    if (!user.rows.length) throw new Error("User not found.");
    if (Number(user.rows[0].balance) < amount) {
      throw new Error("Insufficient wallet balance.");
    }

    await client.query(
      `INSERT INTO payment_requests
       (user_id,type,method,amount,account_number)
       VALUES ($1,'withdraw',$2,$3,$4)`,
      [req.userId, method, amount, account]
    );

    await client.query("COMMIT");
    started = false;

    res.status(201).json({
      message: "Withdrawal request submitted for review."
    });
  } catch (error) {
    if (started) await client.query("ROLLBACK");
    res.status(400).json({ error: error.message || "Could not submit request." });
  } finally {
    client.release();
  }
});// ===============================
// PART 3/5 - ACTIVATION, ORDERS, TEAM & CHAT
// ===============================

// Activate product plan
app.post("/api/activate", auth, async (req, res) => {
  const client = await pool.connect();

  try {
    const userId = req.user.id;
    const productId = Number(req.body.product_id);

    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({ error: "Invalid product" });
    }

    await client.query("BEGIN");

    const productResult = await client.query(
      "SELECT * FROM products WHERE id=$1 AND active=true",
      [productId]
    );

    if (!productResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Product not found" });
    }

    const product = productResult.rows[0];

    const userResult = await client.query(
      "SELECT * FROM users WHERE id=$1 FOR UPDATE",
      [userId]
    );

    if (!userResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "User not found" });
    }

    const price = Number(product.price);

    if (Number(userResult.rows[0].balance) < price) {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Insufficient balance" });
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [price, userId]
    );

    const planResult = await client.query(
      `INSERT INTO plans (user_id, product_id, product_name, amount, status)
       VALUES ($1, $2, $3, $4, 'active')
       RETURNING *`,
      [userId, product.id, product.name, price]
    );

    await client.query(
      `INSERT INTO transactions (user_id, type, amount, status, description)
       VALUES ($1, 'purchase', $2, 'approved', $3)`,
      [userId, price, `Purchased ${product.name}`]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Product activated successfully",
      plan: planResult.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Activate error:", error);
    res.status(500).json({ error: "Could not activate product" });
  } finally {
    client.release();
  }
});

// My orders and transactions
app.get("/api/my-orders", auth, async (req, res) => {
  try {
    const plans = await pool.query(
      `SELECT * FROM plans
       WHERE user_id=$1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    const transactions = await pool.query(
      `SELECT * FROM transactions
       WHERE user_id=$1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json({
      plans: plans.rows,
      transactions: transactions.rows
    });
  } catch (error) {
    console.error("My orders error:", error);
    res.status(500).json({ error: "Could not load orders" });
  }
});

// Team members
app.get("/api/team", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, phone, created_at
       FROM users
       WHERE referred_by=$1
       ORDER BY created_at DESC`,
      [req.user.id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Team error:", error);
    res.status(500).json({ error: "Could not load team" });
  }
});

// Chat history
app.get("/api/chat/history", auth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, message, reply, created_at
       FROM chat_messages
       WHERE user_id=$1
       ORDER BY created_at DESC
       LIMIT 50`,
      [req.user.id]
    );

    res.json(result.rows.reverse());
  } catch (error) {
    console.error("Chat history error:", error);
    res.status(500).json({ error: "Could not load chat history" });
  }
});

// AI chat
app.post("/api/chat", auth, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message) {
      return res.status(400).json({ error: "Message is required" });
    }

    if (message.length > 2000) {
      return res.status(400).json({ error: "Message is too long" });
    }

    const model = process.env.GEMINI_MODEL || "gemini-3.8-flash";
    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return res.status(503).json({
        error: "AI service is not configured"
      });
    }

    const endpoint =
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

    const response = await fetch(endpoint, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-goog-api-key": apiKey
      },
      body: JSON.stringify({
        contents: [
          {
            role: "user",
            parts: [{ text: message }]
          }
        ],
        generationConfig: {
          temperature: 0.7,
          maxOutputTokens: 700
        }
      })
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("Gemini API error:", data);
      return res.status(502).json({
        error: "AI service is temporarily unavailable"
      });
    }

    const reply =
      data.candidates?.[0]?.content?.parts
        ?.map(part => part.text || "")
        .join("\n")
        .trim() || "দুঃখিত, এখন উত্তর দিতে পারছি না।";

    await pool.query(
      `INSERT INTO chat_messages (user_id, message, reply)
       VALUES ($1, $2, $3)`,
      [req.user.id, message, reply]
    );

    res.json({ reply });
  } catch (error) {
    console.error("Chat error:", error);
    res.status(500).json({ error: "Chat service failed" });
  }
});// ===============================
// PART 4/5 - ADMIN PANEL API
// ===============================

// Admin login
app.post("/api/admin/login", adminLoginLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    if (
      email !== String(process.env.ADMIN_EMAIL || "").toLowerCase() ||
      password !== process.env.ADMIN_PASSWORD
    ) {
      return res.status(401).json({ error: "Invalid admin credentials" });
    }

    const token = jwt.sign(
      { role: "admin", email },
      process.env.JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({ token, role: "admin" });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({ error: "Admin login failed" });
  }
});

// Admin users
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, email, phone, balance, created_at
       FROM users ORDER BY created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Admin users error:", error);
    res.status(500).json({ error: "Could not load users" });
  }
});

// Admin products list
app.get("/api/admin/products", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM products ORDER BY id DESC"
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Admin products error:", error);
    res.status(500).json({ error: "Could not load products" });
  }
});

// Add product
app.post("/api/admin/products", adminAuth, async (req, res) => {
  try {
    const { name, description, price, daily_income, duration, image } = req.body;

    if (!name || !validAmount(price)) {
      return res.status(400).json({ error: "Valid name and price required" });
    }

    const result = await pool.query(
      `INSERT INTO products
       (name, description, price, daily_income, duration, image, active)
       VALUES ($1, $2, $3, $4, $5, $6, true)
       RETURNING *`,
      [
        name,
        description || "",
        Number(price),
        Number(daily_income) || 0,
        Number(duration) || 0,
        image || ""
      ]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    console.error("Add product error:", error);
    res.status(500).json({ error: "Could not add product" });
  }
});

// Update product
app.put("/api/admin/products/:id", adminAuth, async (req, res) => {
  try {
    const { name, description, price, daily_income, duration, image, active } = req.body;

    if (!name || !validAmount(price)) {
      return res.status(400).json({ error: "Valid name and price required" });
    }

    const result = await pool.query(
      `UPDATE products SET
       name=$1, description=$2, price=$3, daily_income=$4,
       duration=$5, image=$6, active=$7
       WHERE id=$8 RETURNING *`,
      [
        name,
        description || "",
        Number(price),
        Number(daily_income) || 0,
        Number(duration) || 0,
        image || "",
        active !== false,
        req.params.id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Update product error:", error);
    res.status(500).json({ error: "Could not update product" });
  }
});

// Delete product
app.delete("/api/admin/products/:id", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM products WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "Product not found" });
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Delete product error:", error);
    res.status(500).json({ error: "Could not delete product" });
  }
});

// Payment requests
app.get("/api/admin/payment-requests", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT pr.*, u.name AS user_name, u.phone AS user_phone
       FROM payment_requests pr
       JOIN users u ON u.id=pr.user_id
       ORDER BY pr.created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Admin payment requests error:", error);
    res.status(500).json({ error: "Could not load payment requests" });
  }
});

// Approve or reject payment request
app.patch("/api/admin/payment-requests/:id", adminAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const status = String(req.body.status || "").toLowerCase();

    if (!["approved", "rejected"].includes(status)) {
      return res.status(400).json({ error: "Invalid status" });
    }

    await client.query("BEGIN");

    const requestResult = await client.query(
      "SELECT * FROM payment_requests WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );

    if (!requestResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Request not found" });
    }

    const request = requestResult.rows[0];

    if (request.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(400).json({ error: "Request already processed" });
    }

    await client.query(
      "UPDATE payment_requests SET status=$1 WHERE id=$2",
      [status, request.id]
    );

    if (status === "approved") {
      if (request.type === "deposit") {
        await client.query(
          "UPDATE users SET balance=balance+$1 WHERE id=$2",
          [request.amount, request.user_id]
        );
      } else if (request.type === "withdraw") {
        const userResult = await client.query(
          "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
          [request.user_id]
        );

        if (
          !userResult.rowCount ||
          Number(userResult.rows[0].balance) < Number(request.amount)
        ) {
          await client.query("ROLLBACK");
          return res.status(400).json({ error: "Insufficient user balance" });
        }

        await client.query(
          "UPDATE users SET balance=balance-$1 WHERE id=$2",
          [request.amount, request.user_id]
        );
      }

      await client.query(
        `INSERT INTO transactions (user_id, type, amount, status, description)
         VALUES ($1, $2, $3, 'approved', $4)`,
        [
          request.user_id,
          request.type,
          request.amount,
          `${request.type} request approved`
        ]
      );
    }

    await client.query("COMMIT");

    res.json({ success: true, status });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Payment approval error:", error);
    res.status(500).json({ error: "Could not process payment request" });
  } finally {
    client.release();
  }
});

// Admin chat escalations
app.get("/api/admin/chat-escalations", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM chat_escalations
       ORDER BY created_at DESC LIMIT 100`
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Chat escalations error:", error);
    res.status(500).json({ error: "Could not load escalations" });
  }
});

// App management API
app.use("/api", require("./app-management"));// ===============================
// PART 5/5 - ERROR HANDLING & START
// ===============================

// Not found
app.use((req, res) => {
  res.status(404).json({
    error: "API endpoint not found"
  });
});

// General error handler
app.use((error, req, res, next) => {
  console.error("Server error:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "Internal server error"
  });
});

// Start server
initDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`SKYPAY server running on port ${PORT}`);
    });
  })
  .catch((error) => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
