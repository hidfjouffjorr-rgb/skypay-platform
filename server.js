// ======================================
// SKYPAY SERVER - UPDATED FULL CODE
// ======================================

const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype || !file.mimetype.startsWith("image/")) {
      return cb(new Error("Only image files are allowed."));
    }
    cb(null, true);
  }
});

const app = express();
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;

const requiredEnv = [
  "DATABASE_URL",
  "JWT_SECRET",
  "ADMIN_EMAIL",
  "ADMIN_PASSWORD_HASH"
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`Missing environment variable: ${key}`);
    process.exit(1);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

pool.on("error", error => {
  console.error("Unexpected database error:", error);
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
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
  limit: 10
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
      throw new Error("Invalid user token");
    }

    req.userId = decoded.id;
    next();
  } catch (error) {
    return res.status(401).json({
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
      throw new Error("Invalid admin token");
    }

    req.admin = decoded;
    next();
  } catch (error) {
    return res.status(401).json({
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

async function sendTelegramMessage(message) {
  const botToken = process.env.TELEGRAM_BOT_TOKEN;

  const chatId =
    process.env.TELEGRAM_CHAT_ID ||
    process.env.TELEGRAM_ADMIN_CHAT_ID ||
    "6804193991";

  if (!botToken) {
    console.error("Telegram Bot Token is missing.");
    return false;
  }

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${botToken}/sendMessage`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
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
    console.error("Telegram notification error:", error.message);
    return false;
  }
}

function uploadImageToCloudinary(buffer, folder = "skypay/products") {
  return new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream(
      {
        folder,
        resource_type: "image"
      },
      (error, result) => {
        if (error) return reject(error);
        resolve(result);
      }
    );

    stream.end(buffer);
  });
}

// ======================================
// DATABASE INITIALIZATION
// ======================================

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

    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      type VARCHAR(30) NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      description TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS referral_commissions (
      id SERIAL PRIMARY KEY,
      deposit_request_id INTEGER UNIQUE
        REFERENCES payment_requests(id) ON DELETE CASCADE,
      referrer_user_id INTEGER NOT NULL REFERENCES users(id),
      referred_user_id INTEGER NOT NULL REFERENCES users(id),
      deposit_amount NUMERIC(14,2) NOT NULL,
      commission_amount NUMERIC(14,2) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'available',
      claimed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS referral_commissions_owner_idx
    ON referral_commissions(referrer_user_id, status);
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

    CREATE TABLE IF NOT EXISTS chat_escalations (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      message TEXT NOT NULL,
      reason TEXT DEFAULT '',
      status VARCHAR(20) NOT NULL DEFAULT 'pending',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS managed_apps (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      size TEXT DEFAULT '',
      download_url TEXT NOT NULL,
      image_url TEXT DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );

    ALTER TABLE managed_apps
    ADD COLUMN IF NOT EXISTS image_url TEXT DEFAULT '';
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS payment_settings (
      id INTEGER PRIMARY KEY DEFAULT 1,
      bkash_number VARCHAR(40) NOT NULL DEFAULT '+8801763341991',
      nagad_number VARCHAR(40) NOT NULL DEFAULT '+8801985052780',
      bkash_logo TEXT DEFAULT '',
      nagad_logo TEXT DEFAULT '',
      bkash_type VARCHAR(20) NOT NULL DEFAULT 'send_money',
      nagad_type VARCHAR(20) NOT NULL DEFAULT 'send_money',
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    ALTER TABLE payment_settings
    ADD COLUMN IF NOT EXISTS bkash_type VARCHAR(20)
    NOT NULL DEFAULT 'send_money';

    ALTER TABLE payment_settings
    ADD COLUMN IF NOT EXISTS nagad_type VARCHAR(20)
    NOT NULL DEFAULT 'send_money';

    INSERT INTO payment_settings (id)
    VALUES (1)
    ON CONFLICT (id) DO NOTHING;
  `);

  const productCount = await pool.query(
    "SELECT COUNT(*) FROM products"
  );

  if (Number(productCount.rows[0].count) === 0) {
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
        [
          name,
          "Please ask the administrator for product details."
        ]
      );
    }
  }

  console.log("SKYPAY database ready.");
}

// ======================================
// HEALTH CHECK
// ======================================

app.get("/api/health", (req, res) => {
  res.json({
    success: true,
    status: "online",
    service: "SKYPAY"
  });
});

// ======================================
// USER REGISTRATION
// ======================================

app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");
    const referralCode = String(req.body.referral_code || "").trim();

    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({ error: "Enter a valid name." });
    }

    if (phone.length < 7 || phone.length > 30) {
      return res.status(400).json({ error: "Enter a valid phone number." });
    }

    if (password.length < 6 || password.length > 100) {
      return res.status(400).json({
        error: "Password must be 6 to 100 characters."
      });
    }

    const existing = await pool.query(
      "SELECT id FROM users WHERE phone=$1",
      [phone]
    );

    if (existing.rowCount) {
      return res.status(409).json({
        error: "This phone number is already registered."
      });
    }

    let referredBy = null;

    if (referralCode) {
      const referrer = await pool.query(
        "SELECT id FROM users WHERE referral_code=$1",
        [referralCode]
      );

      if (!referrer.rowCount) {
        return res.status(400).json({
          error: "Invalid referral code."
        });
      }

      referredBy = referrer.rows[0].id;
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const uid = "SKY" + Date.now().toString(36).toUpperCase();
    const newReferralCode =
      "SKY" + Math.random().toString(36).slice(2, 9).toUpperCase();

    const result = await pool.query(
      `INSERT INTO users
       (uid, username, name, phone, password_hash,
        referral_code, referred_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING id, uid, name, phone, referral_code, balance`,
      [
        uid,
        phone,
        name,
        phone,
        passwordHash,
        newReferralCode,
        referredBy
      ]
    );

    const user = result.rows[0];
    const token = makeToken({
      id: user.id,
      role: "user"
    });

    res.status(201).json({
      success: true,
      token,
      user
    });
  } catch (error) {
    console.error("Registration error:", error);
    res.status(500).json({
      error: "Registration failed."
    });
  }
});

// ======================================
// USER LOGIN
// ======================================

app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    if (!phone || !password) {
      return res.status(400).json({
        error: "Phone and password are required."
      });
    }

    const result = await pool.query(
      "SELECT * FROM users WHERE phone=$1",
      [phone]
    );

    if (!result.rowCount) {
      return res.status(401).json({
        error: "Invalid phone number or password."
      });
    }

    const user = result.rows[0];

    if (user.status && user.status !== "active") {
      return res.status(403).json({
        error: "Your account is not active."
      });
    }

    const passwordMatch = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatch) {
      return res.status(401).json({
        error: "Invalid phone number or password."
      });
    }

    const token = makeToken({
      id: user.id,
      role: "user"
    });

    res.json({
      success: true,
      token,
      user: {
        id: user.id,
        uid: user.uid,
        name: user.name,
        phone: user.phone,
        balance: user.balance,
        referral_code: user.referral_code
      }
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({
      error: "Login failed."
    });
  }
});

// ======================================
// PUBLIC PRODUCTS
// ======================================

app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, price, duration_days,
              daily_estimate, image_url, description
       FROM products
       WHERE active=true
       ORDER BY id ASC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Products error:", error);
    res.status(500).json({
      error: "Could not load products."
    });
  }
});

// ======================================
// USER PROFILE
// ======================================

app.get("/api/profile", userAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, uid, username, name, phone,
              balance, total_deposit, total_withdraw,
              referral_code, created_at
       FROM users WHERE id=$1`,
      [req.userId]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error("Profile error:", error);
    res.status(500).json({
      error: "Could not load profile."
    });
  }
});

// ======================================
// VERIFY USER SESSION
// ======================================

app.get("/api/me", userAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, uid, username, name, phone,
              balance, total_deposit, total_withdraw,
              referral_code, created_at
       FROM users WHERE id=$1`,
      [req.userId]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    res.json({
      success: true,
      user: result.rows[0]
    });
  } catch (error) {
    console.error("Me API error:", error);
    res.status(500).json({
      error: "Could not verify user session."
    });
  }
});

// ======================================
// DEPOSIT REQUEST - MINIMUM ৳500
// ======================================

app.post("/api/deposit", userAuth, async (req, res) => {
  try {
    const amount = Number(req.body.amount);
    const method = String(req.body.method || "").toLowerCase();
    const senderNumber = normalizePhone(req.body.sender_number);
    const transactionId = String(req.body.transaction_id || "").trim();

    if (!validAmount(amount) || amount < 500) {
      return res.status(400).json({
        error: "Minimum deposit amount is ৳500."
      });
    }

    if (!["bkash", "nagad"].includes(method)) {
      return res.status(400).json({
        error: "Invalid payment method."
      });
    }

    if (!senderNumber || !transactionId) {
      return res.status(400).json({
        error: "Sender number and transaction ID are required."
      });
    }

    const result = await pool.query(
      `INSERT INTO payment_requests
       (user_id, type, method, amount, sender_number, transaction_id)
       VALUES ($1, 'deposit', $2, $3, $4, $5)
       RETURNING id, status, amount, created_at`,
      [
        req.userId,
        method,
        amount,
        senderNumber,
        transactionId
      ]
    );

    await pool.query(
      `INSERT INTO transactions
       (user_id, type, amount, status, description)
       VALUES ($1, 'deposit', $2, 'pending', $3)`,
      [req.userId, amount, `${method} deposit request`]
    );

    await sendTelegramMessage(
      `SKYPAY Deposit Request\nAmount: ${amount}\nMethod: ${method}\nSender: ${senderNumber}\nTransaction: ${transactionId}`
    );

    res.status(201).json({
      success: true,
      request: result.rows[0]
    });
  } catch (error) {
    console.error("Deposit error:", error);
    res.status(500).json({
      error: "Could not submit deposit request."
    });
  }
});

// ======================================
// WITHDRAWAL REQUEST
// ======================================

app.post("/api/withdraw", userAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const amount = Number(req.body.amount);
    const method = String(req.body.method || "").toLowerCase();
    const accountNumber = normalizePhone(req.body.account_number);

    if (!validAmount(amount) || amount < 1000) {
      return res.status(400).json({
        error: "Minimum withdrawal amount is ৳1,000."
      });
    }

    if (!["bkash", "nagad"].includes(method)) {
      return res.status(400).json({
        error: "Invalid payment method."
      });
    }

    if (!accountNumber) {
      return res.status(400).json({
        error: "Account number is required."
      });
    }

    await client.query("BEGIN");

    const userResult = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [req.userId]
    );

    if (!userResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        error: "User not found."
      });
    }

    if (Number(userResult.rows[0].balance) < amount) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "Insufficient balance."
      });
    }

    const countResult = await client.query(
      `SELECT COUNT(*)::int AS total
       FROM payment_requests
       WHERE user_id=$1
         AND type='withdraw'
         AND created_at >= NOW() - INTERVAL '24 hours'`,
      [req.userId]
    );

    if (countResult.rows[0].total >= 3) {
      await client.query("ROLLBACK");
      return res.status(429).json({
        error: "You can submit a maximum of 3 withdrawal requests in 24 hours."
      });
    }

    const result = await client.query(
      `INSERT INTO payment_requests
       (user_id, type, method, amount, account_number)
       VALUES ($1, 'withdraw', $2, $3, $4)
       RETURNING id, status, amount, created_at`,
      [req.userId, method, amount, accountNumber]
    );

    await client.query(
      `INSERT INTO transactions
       (user_id, type, amount, status, description)
       VALUES ($1, 'withdraw', $2, 'pending', $3)`,
      [req.userId, amount, `${method} withdrawal request`]
    );

    await client.query("COMMIT");

    await sendTelegramMessage(
      `SKYPAY Withdrawal Request\nAmount: ${amount}\nMethod: ${method}\nAccount: ${accountNumber}`
    );

    res.status(201).json({
      success: true,
      request: result.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Withdrawal error:", error);
    res.status(500).json({
      error: "Could not submit withdrawal request."
    });
  } finally {
    client.release();
  }
});

// ======================================
// ACTIVATE PRODUCT
// ======================================

app.post("/api/activate", userAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const productId = Number(req.body.product_id);

    if (!Number.isInteger(productId) || productId <= 0) {
      return res.status(400).json({
        error: "Invalid product."
      });
    }

    await client.query("BEGIN");

    const productResult = await client.query(
      "SELECT * FROM products WHERE id=$1 AND active=true",
      [productId]
    );

    if (!productResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        error: "Product not found."
      });
    }

    const product = productResult.rows[0];

    if (!validAmount(product.price)) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "This product is not available for purchase."
      });
    }

    const userResult = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [req.userId]
    );

    if (
      !userResult.rowCount ||
      Number(userResult.rows[0].balance) < Number(product.price)
    ) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "Insufficient balance."
      });
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [product.price, req.userId]
    );

    const planResult = await client.query(
      `INSERT INTO plans
       (user_id, product_id, product_name, price,
        daily_estimate, duration_days, status)
       VALUES ($1, $2, $3, $4, $5, $6, 'active')
       RETURNING *`,
      [
        req.userId,
        product.id,
        product.name,
        product.price,
        product.daily_estimate,
        product.duration_days
      ]
    );

    await client.query(
      `INSERT INTO transactions
       (user_id, type, amount, status, description)
       VALUES ($1, 'purchase', $2, 'approved', $3)`,
      [req.userId, product.price, `Purchased ${product.name}`]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      message: "Product activated successfully.",
      plan: planResult.rows[0]
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Activation error:", error);
    res.status(500).json({
      error: "Could not activate product."
    });
  } finally {
    client.release();
  }
});

// ======================================
// MY ORDERS
// ======================================

app.get("/api/my-orders", userAuth, async (req, res) => {
  try {
    const plans = await pool.query(
      `SELECT * FROM plans
       WHERE user_id=$1
       ORDER BY created_at DESC`,
      [req.userId]
    );

    const transactions = await pool.query(
      `SELECT * FROM transactions
       WHERE user_id=$1
       ORDER BY created_at DESC`,
      [req.userId]
    );

    res.json({
      plans: plans.rows,
      transactions: transactions.rows
    });
  } catch (error) {
    console.error("Orders error:", error);
    res.status(500).json({
      error: "Could not load orders."
    });
  }
});

// ======================================
// TEAM MEMBERS
// ======================================

app.get("/api/team", userAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, uid, name, phone, created_at
       FROM users
       WHERE referred_by=$1
       ORDER BY created_at DESC`,
      [req.userId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Team error:", error);
    res.status(500).json({
      error: "Could not load team."
    });
  }
});

// ======================================
// REFERRAL SUMMARY
// ======================================

app.get("/api/referral/summary", userAuth, async (req, res) => {
  try {
    const teamResult = await pool.query(
      `SELECT COUNT(*)::int AS total
       FROM users
       WHERE referred_by=$1`,
      [req.userId]
    );

    const commissionResult = await pool.query(
      `SELECT
         COALESCE(SUM(commission_amount), 0) AS total_commission,
         COALESCE(SUM(
           CASE WHEN status='available'
           THEN commission_amount ELSE 0 END
         ), 0) AS available_commission,
         COALESCE(SUM(
           CASE WHEN status='claimed'
           THEN commission_amount ELSE 0 END
         ), 0) AS claimed_commission
       FROM referral_commissions
       WHERE referrer_user_id=$1`,
      [req.userId]
    );

    res.json({
      success: true,
      team_count: teamResult.rows[0].total,
      total_commission: Number(
        commissionResult.rows[0].total_commission
      ),
      available_commission: Number(
        commissionResult.rows[0].available_commission
      ),
      claimed_commission: Number(
        commissionResult.rows[0].claimed_commission
      ),
      commission_rate: 10
    });
  } catch (error) {
    console.error("Referral summary error:", error);
    res.status(500).json({
      error: "Could not load referral summary."
    });
  }
});

// ======================================
// CLAIM REFERRAL COMMISSION
// ======================================

app.post("/api/referral/claim", userAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const userResult = await client.query(
      "SELECT id FROM users WHERE id=$1 FOR UPDATE",
      [req.userId]
    );

    if (!userResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        error: "User not found."
      });
    }

    const availableResult = await client.query(
      `SELECT COALESCE(SUM(commission_amount), 0) AS total
       FROM referral_commissions
       WHERE referrer_user_id=$1
         AND status='available'`,
      [req.userId]
    );

    const amount = Number(availableResult.rows[0].total);

    if (!Number.isFinite(amount) || amount <= 0) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "No referral commission available to claim."
      });
    }

    const claimedResult = await client.query(
      `UPDATE referral_commissions
       SET status='claimed', claimed_at=NOW()
       WHERE referrer_user_id=$1
         AND status='available'
       RETURNING id`,
      [req.userId]
    );

    if (!claimedResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "No referral commission available to claim."
      });
    }

    await client.query(
      "UPDATE users SET balance=balance+$1 WHERE id=$2",
      [amount, req.userId]
    );

    await client.query(
      `INSERT INTO transactions
       (user_id, type, amount, status, description)
       VALUES ($1, 'referral_commission', $2, 'approved', $3)`,
      [
        req.userId,
        amount,
        "Referral commission claimed to main wallet"
      ]
    );

    await client.query("COMMIT");

    res.json({
      success: true,
      claimed_amount: amount,
      message: "Referral commission added to your main wallet."
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Referral claim error:", error);
    res.status(500).json({
      error: "Could not claim referral commission."
    });
  } finally {
    client.release();
  }
});

// ======================================
// CHAT HISTORY
// ======================================

app.get("/api/chat/history", userAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, role, content, created_at
       FROM chat_messages
       WHERE user_id=$1
       ORDER BY created_at ASC
       LIMIT 100`,
      [req.userId]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Chat history error:", error);
    res.status(500).json({
      error: "Could not load chat history."
    });
  }
});

// ======================================
// AI CHAT
// ======================================

app.post("/api/chat", userAuth, chatLimiter, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message || message.length > 2000) {
      return res.status(400).json({
        error: "Message must be between 1 and 2000 characters."
      });
    }

    const apiKey = process.env.GEMINI_API_KEY;

    if (!apiKey) {
      return res.status(503).json({
        error: "AI service is not configured."
      });
    }

    const model = process.env.GEMINI_MODEL || "gemini-2.5-flash";

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
      console.error("Gemini error:", data);
      return res.status(502).json({
        error: "AI service is temporarily unavailable."
      });
    }

    const reply = data.candidates?.[0]?.content?.parts
      ?.map(part => part.text || "")
      .join("\n")
      .trim();

    if (!reply) {
      return res.status(502).json({
        error: "AI returned an empty response."
      });
    }

    await pool.query(
      `INSERT INTO chat_messages (user_id, role, content)
       VALUES ($1, 'user', $2), ($1, 'assistant', $3)`,
      [req.userId, message, reply]
    );

    res.json({
      success: true,
      reply
    });
  } catch (error) {
    console.error("Chat error:", error);
    res.status(500).json({
      error: "Chat service failed."
    });
  }
});

// ======================================
// ADMIN LOGIN
// ======================================

app.post("/api/admin/login", adminLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const adminEmail =
      String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();

    const passwordHash = process.env.ADMIN_PASSWORD_HASH;

    if (!email || !password || email !== adminEmail || !passwordHash) {
      return res.status(401).json({
        error: "Invalid admin credentials."
      });
    }

    const validPassword = await bcrypt.compare(password, passwordHash);

    if (!validPassword) {
      return res.status(401).json({
        error: "Invalid admin credentials."
      });
    }

    const token = jwt.sign(
      { role: "admin", email },
      process.env.JWT_SECRET,
      { expiresIn: "12h" }
    );

    res.json({
      success: true,
      token,
      role: "admin"
    });
  } catch (error) {
    console.error("Admin login error:", error);
    res.status(500).json({
      error: "Admin login failed."
    });
  }
});

// ======================================
// VERIFY ADMIN SESSION
// ======================================

app.get("/api/admin/me", adminAuth, (req, res) => {
  res.json({
    success: true,
    role: "admin",
    email: req.admin.email
  });
});

// ======================================
// CLOUDINARY IMAGE UPLOAD
// ======================================

app.post(
  "/api/admin/upload-image",
  adminAuth,
  (req, res, next) => {
    upload.single("image")(req, res, error => {
      if (error) {
        return res.status(400).json({
          error: error.message || "Image upload error."
        });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      if (
        !process.env.CLOUDINARY_CLOUD_NAME ||
        !process.env.CLOUDINARY_API_KEY ||
        !process.env.CLOUDINARY_API_SECRET
      ) {
        return res.status(503).json({
          error: "Image storage is not configured."
        });
      }

      if (!req.file) {
        return res.status(400).json({
          error: "Please choose an image."
        });
      }

      const result = await uploadImageToCloudinary(req.file.buffer);

      res.status(201).json({
        success: true,
        url: result.secure_url,
        public_id: result.public_id
      });
    } catch (error) {
      console.error("Image upload error:", error.message);
      res.status(500).json({
        error: "Could not upload image."
      });
    }
  }
);

// ======================================
// ADMIN DASHBOARD STATS
// ======================================

app.get("/api/admin/stats", adminAuth, async (req, res) => {
  try {
    const users = await pool.query(
      "SELECT COUNT(*) FROM users"
    );

    const deposits = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total
       FROM payment_requests
       WHERE type='deposit' AND status='approved'`
    );

    const withdrawals = await pool.query(
      `SELECT COALESCE(SUM(amount), 0) AS total
       FROM payment_requests
       WHERE type='withdraw' AND status='approved'`
    );

    const pending = await pool.query(
      "SELECT COUNT(*) FROM payment_requests WHERE status='pending'"
    );

    res.json({
      users: Number(users.rows[0].count),
      deposits: Number(deposits.rows[0].total),
      withdrawals: Number(withdrawals.rows[0].total),
      pending_requests: Number(pending.rows[0].count)
    });
  } catch (error) {
    console.error("Admin stats error:", error);
    res.status(500).json({
      error: "Could not load dashboard statistics."
    });
  }
});

// ======================================
// ADMIN USERS
// ======================================

app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, uid, name, phone, balance, status, created_at
       FROM users
       ORDER BY created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Admin users error:", error);
    res.status(500).json({
      error: "Could not load users."
    });
  }
});

// ======================================
// ADMIN PRODUCTS - LIST
// ======================================

app.get("/api/admin/products", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM products ORDER BY id DESC"
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Admin products error:", error);
    res.status(500).json({
      error: "Could not load products."
    });
  }
});

// ======================================
// ADMIN PRODUCTS - ADD
// ======================================

app.post("/api/admin/products", adminAuth, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const price = Number(req.body.price);
    const duration = Number(req.body.duration_days);
    const daily = Number(req.body.daily_estimate);

    if (!name || name.length > 120 || !validAmount(price)) {
      return res.status(400).json({
        error: "Enter a valid product name and price."
      });
    }

    if (
      !Number.isInteger(duration) ||
      duration < 1 ||
      !validAmountOrZero(daily)
    ) {
      return res.status(400).json({
        error: "Invalid duration or daily estimate."
      });
    }

    const result = await pool.query(
      `INSERT INTO products
       (name, price, duration_days, daily_estimate,
        image_url, description, active)
       VALUES ($1, $2, $3, $4, $5, $6, true)
       RETURNING *`,
      [
        name,
        price,
        duration,
        daily,
        String(req.body.image_url || ""),
        String(req.body.description || "")
      ]
    );

    res.status(201).json({
      success: true,
      product: result.rows[0]
    });
  } catch (error) {
    console.error("Add product error:", error);
    res.status(500).json({
      error: "Could not add product."
    });
  }
});

// ======================================
// ADMIN PRODUCTS - EDIT
// ======================================

app.put("/api/admin/products/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const name = String(req.body.name || "").trim();
    const price = Number(req.body.price);
    const duration = Number(req.body.duration_days);
    const daily = Number(req.body.daily_estimate);

    if (
      !Number.isInteger(id) ||
      id <= 0 ||
      !name ||
      name.length > 120 ||
      !validAmount(price) ||
      !Number.isInteger(duration) ||
      duration < 1 ||
      !validAmountOrZero(daily)
    ) {
      return res.status(400).json({
        error: "Invalid product information."
      });
    }

    const result = await pool.query(
      `UPDATE products SET
       name=$1,
       price=$2,
       duration_days=$3,
       daily_estimate=$4,
       image_url=$5,
       description=$6,
       active=$7
       WHERE id=$8
       RETURNING *`,
      [
        name,
        price,
        duration,
        daily,
        String(req.body.image_url || ""),
        String(req.body.description || ""),
        req.body.active !== false,
        id
      ]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Product not found."
      });
    }

    res.json({
      success: true,
      product: result.rows[0]
    });
  } catch (error) {
    console.error("Edit product error:", error);
    res.status(500).json({
      error: "Could not update product."
    });
  }
});

// ======================================
// ADMIN PRODUCTS - DELETE
// ======================================

app.delete("/api/admin/products/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        error: "Invalid product ID."
      });
    }

    const result = await pool.query(
      "DELETE FROM products WHERE id=$1 RETURNING id",
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "Product not found."
      });
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Delete product error:", error);
    res.status(500).json({
      error: "Could not delete product."
    });
  }
});

// ======================================
// ADMIN PAYMENT REQUESTS - LIST
// ======================================

app.get("/api/admin/payment-requests", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT p.*, u.name AS user_name, u.phone AS user_phone
       FROM payment_requests p
       JOIN users u ON u.id=p.user_id
       ORDER BY p.created_at DESC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Payment requests error:", error);
    res.status(500).json({
      error: "Could not load payment requests."
    });
  }
});

// ======================================
// APPROVE OR REJECT PAYMENT REQUEST
// ======================================

app.patch("/api/admin/payment-requests/:id", adminAuth, async (req, res) => {
  const client = await pool.connect();

  try {
    const id = Number(req.params.id);
    const status = String(req.body.status || "").toLowerCase();

    if (
      !Number.isInteger(id) ||
      id <= 0 ||
      !["approved", "rejected"].includes(status)
    ) {
      return res.status(400).json({
        error: "Invalid request."
      });
    }

    await client.query("BEGIN");

    const requestResult = await client.query(
      "SELECT * FROM payment_requests WHERE id=$1 FOR UPDATE",
      [id]
    );

    if (!requestResult.rowCount) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        error: "Request not found."
      });
    }

    const request = requestResult.rows[0];

    if (request.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "Request has already been processed."
      });
    }

    if (status === "approved") {
      const userResult = await client.query(
        "SELECT id, balance, referred_by FROM users WHERE id=$1 FOR UPDATE",
        [request.user_id]
      );

      if (!userResult.rowCount) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          error: "User not found."
        });
      }

      const depositUser = userResult.rows[0];

      if (request.type === "deposit") {
        await client.query(
          `UPDATE users
           SET balance=balance+$1,
               total_deposit=total_deposit+$1
           WHERE id=$2`,
          [request.amount, request.user_id]
        );

        if (depositUser.referred_by) {
          await client.query(
            `INSERT INTO referral_commissions
             (deposit_request_id, referrer_user_id,
              referred_user_id, deposit_amount, commission_amount)
             VALUES ($1, $2, $3, $4, ROUND($4::numeric * 0.10, 2))
             ON CONFLICT (deposit_request_id) DO NOTHING`,
            [
              request.id,
              depositUser.referred_by,
              request.user_id,
              request.amount
            ]
          );
        }
      } else if (request.type === "withdraw") {
        if (Number(depositUser.balance) < Number(request.amount)) {
          await client.query("ROLLBACK");
          return res.status(400).json({
            error: "Insufficient user balance."
          });
        }

        await client.query(
          `UPDATE users
           SET balance=balance-$1,
               total_withdraw=total_withdraw+$1
           WHERE id=$2`,
          [request.amount, request.user_id]
        );
      }
    }

    await client.query(
      `UPDATE payment_requests
       SET status=$1, reviewed_at=NOW()
       WHERE id=$2`,
      [status, id]
    );

    await client.query(
      `UPDATE transactions
       SET status=$1
       WHERE id=(
         SELECT id FROM transactions
         WHERE user_id=$2
           AND type=$3
           AND amount=$4
           AND status='pending'
         ORDER BY created_at DESC
         LIMIT 1
       )`,
      [status, request.user_id, request.type, request.amount]
    );

    await client.query("COMMIT");

    await sendTelegramMessage(
      `SKYPAY payment request ${status.toUpperCase()}\nRequest ID: ${id}\nAmount: ${request.amount}`
    );

    res.json({
      success: true,
      status
    });
  } catch (error) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Payment processing error:", error);
    res.status(500).json({
      error: "Could not process payment request."
    });
  } finally {
    client.release();
  }
});

// ======================================
// ADMIN CHAT ESCALATIONS
// ======================================

app.get("/api/admin/chat-escalations", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM chat_escalations
       ORDER BY created_at DESC
       LIMIT 100`
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Escalations error:", error);
    res.status(500).json({
      error: "Could not load escalations."
    });
  }
});

// ======================================
// PUBLIC APP LIST
// ======================================

app.get("/api/apps", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, name, version, size, download_url, image_url, created_at
       FROM managed_apps
       ORDER BY id DESC`
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Apps list error:", error);
    res.status(500).json({
      error: "Could not load apps."
    });
  }
});

// ======================================
// ADMIN ADD APP
// ======================================

app.post("/api/admin/apps", adminAuth, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const version = String(req.body.version || "").trim();
    const size = String(req.body.size || "").trim();
    const downloadUrl = String(req.body.download_url || "").trim();
    const imageUrl = String(req.body.image_url || "").trim();

    if (!name || !version || !downloadUrl) {
      return res.status(400).json({
        error: "App name, version and download URL are required."
      });
    }

    let parsedUrl;

    try {
      parsedUrl = new URL(downloadUrl);
    } catch {
      return res.status(400).json({
        error: "Invalid download URL."
      });
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return res.status(400).json({
        error: "Only HTTP and HTTPS download links are allowed."
      });
    }

    const result = await pool.query(
      `INSERT INTO managed_apps
       (name, version, size, download_url, image_url)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [name, version, size, downloadUrl, imageUrl]
    );

    res.status(201).json({
      success: true,
      app: result.rows[0]
    });
  } catch (error) {
    console.error("Add app error:", error);
    res.status(500).json({
      error: "Could not add app."
    });
  }
});

// ======================================
// ADMIN EDIT APP
// ======================================

app.put("/api/admin/apps/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);
    const name = String(req.body.name || "").trim();
    const version = String(req.body.version || "").trim();
    const size = String(req.body.size || "").trim();
    const downloadUrl = String(req.body.download_url || "").trim();
    const imageUrl = String(req.body.image_url || "").trim();

    if (
      !Number.isInteger(id) ||
      id <= 0 ||
      !name ||
      !version ||
      !downloadUrl
    ) {
      return res.status(400).json({
        error: "Invalid app information."
      });
    }

    let parsedUrl;

    try {
      parsedUrl = new URL(downloadUrl);
    } catch {
      return res.status(400).json({
        error: "Invalid download URL."
      });
    }

    if (!["http:", "https:"].includes(parsedUrl.protocol)) {
      return res.status(400).json({
        error: "Only HTTP and HTTPS download links are allowed."
      });
    }

    const result = await pool.query(
      `UPDATE managed_apps
       SET name=$1, version=$2, size=$3, download_url=$4, image_url=$5
       WHERE id=$6
       RETURNING *`,
      [name, version, size, downloadUrl, imageUrl, id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "App not found."
      });
    }

    res.json({
      success: true,
      app: result.rows[0]
    });
  } catch (error) {
    console.error("Edit app error:", error);
    res.status(500).json({
      error: "Could not update app."
    });
  }
});

// ======================================
// ADMIN DELETE APP
// ======================================

app.delete("/api/admin/apps/:id", adminAuth, async (req, res) => {
  try {
    const id = Number(req.params.id);

    if (!Number.isInteger(id) || id <= 0) {
      return res.status(400).json({
        error: "Invalid app ID."
      });
    }

    const result = await pool.query(
      "DELETE FROM managed_apps WHERE id=$1 RETURNING id",
      [id]
    );

    if (!result.rowCount) {
      return res.status(404).json({
        error: "App not found."
      });
    }

    res.json({ success: true });
  } catch (error) {
    console.error("Delete app error:", error);
    res.status(500).json({
      error: "Could not delete app."
    });
  }
});

// ======================================
// PAYMENT SETTINGS
// ======================================

app.get("/api/payment-settings", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT bkash_number, nagad_number,
              bkash_logo, nagad_logo,
              bkash_type, nagad_type
       FROM payment_settings
       WHERE id=1`
    );

    res.json(result.rows[0] || {});
  } catch (error) {
    console.error("Payment settings error:", error);
    res.status(500).json({
      error: "Could not load payment settings."
    });
  }
});

app.get("/api/admin/payment-settings", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM payment_settings WHERE id=1"
    );

    res.json(result.rows[0] || {});
  } catch (error) {
    console.error("Admin payment settings error:", error);
    res.status(500).json({
      error: "Could not load payment settings."
    });
  }
});

app.put("/api/admin/payment-settings", adminAuth, async (req, res) => {
  try {
    const bkash = normalizePhone(req.body.bkash_number);
    const nagad = normalizePhone(req.body.nagad_number);

    const bkashLogo = String(req.body.bkash_logo || "");
    const nagadLogo = String(req.body.nagad_logo || "");

    const bkashType = String(req.body.bkash_type || "send_money");
    const nagadType = String(req.body.nagad_type || "send_money");

    if (!bkash || !nagad) {
      return res.status(400).json({
        error: "Both payment numbers are required."
      });
    }

    if (
      !["send_money", "cash_out"].includes(bkashType) ||
      !["send_money", "cash_out"].includes(nagadType)
    ) {
      return res.status(400).json({
        error: "Invalid payment transaction type."
      });
    }

    await pool.query(
      `UPDATE payment_settings
       SET bkash_number=$1,
           nagad_number=$2,
           bkash_logo=$3,
           nagad_logo=$4,
           bkash_type=$5,
           nagad_type=$6,
           updated_at=NOW()
       WHERE id=1`,
      [
        bkash,
        nagad,
        bkashLogo,
        nagadLogo,
        bkashType,
        nagadType
      ]
    );

    res.json({
      success: true,
      message: "Payment settings saved."
    });
  } catch (error) {
    console.error("Payment settings save error:", error);
    res.status(500).json({
      error: "Could not save payment settings."
    });
  }
});

app.post(
  "/api/admin/payment-logo",
  adminAuth,
  (req, res, next) => {
    upload.single("image")(req, res, error => {
      if (error) {
        return res.status(400).json({
          error: error.message || "Image upload error."
        });
      }
      next();
    });
  },
  async (req, res) => {
    try {
      const method = String(req.body.method || "").toLowerCase();

      if (!["bkash", "nagad"].includes(method)) {
        return res.status(400).json({
          error: "Select bKash or Nagad."
        });
      }

      if (!req.file) {
        return res.status(400).json({
          error: "Please choose a logo image."
        });
      }

      if (
        !process.env.CLOUDINARY_CLOUD_NAME ||
        !process.env.CLOUDINARY_API_KEY ||
        !process.env.CLOUDINARY_API_SECRET
      ) {
        return res.status(503).json({
          error: "Cloudinary is not configured."
        });
      }

      const result = await uploadImageToCloudinary(
        req.file.buffer,
        "skypay/payment-logos"
      );

      res.status(201).json({
        success: true,
        url: result.secure_url
      });
    } catch (error) {
      console.error("Payment logo upload error:", error);
      res.status(500).json({
        error: "Could not upload payment logo."
      });
    }
  }
);

// ======================================
// API NOT FOUND
// ======================================

app.use("/api", (req, res) => {
  res.status(404).json({
    error: "API endpoint not found."
  });
});

// ======================================
// GENERAL ERROR HANDLER
// ======================================

app.use((error, req, res, next) => {
  console.error("Server error:", error);

  if (res.headersSent) {
    return next(error);
  }

  res.status(500).json({
    error: "Internal server error."
  });
});

// ======================================
// START SERVER
// ======================================

initDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`SKYPAY server running on port ${PORT}`);
    });
  })
  .catch(error => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
