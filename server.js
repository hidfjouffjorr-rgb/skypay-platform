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
}

// HEALTH CHECK
app.get("/api/health", (req, res) => {
  res.json({
    status: "ok",
    app: "SKYPAY"
  });
});

// REGISTRATION
app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");
    const referralCode = String(req.body.referralCode || "").trim();

    if (name.length < 2 || name.length > 100) {
      return res.status(400).json({
        error: "Enter a valid name."
      });
    }

    if (!/^\+?[0-9]{8,16}$/.test(phone)) {
      return res.status(400).json({
        error: "Enter a valid phone number."
      });
    }

    if (password.length < 6 || password.length > 100) {
      return res.status(400).json({
        error: "Password must be at least 6 characters."
      });
    }

    const duplicate = await pool.query(
      "SELECT id FROM users WHERE phone=$1",
      [phone]
    );

    if (duplicate.rows.length) {
      return res.status(409).json({
        error: "This phone number is already registered."
      });
    }

    let referrer = null;

    if (referralCode) {
      const found = await pool.query(
        "SELECT id FROM users WHERE referral_code=$1",
        [referralCode]
      );

      if (found.rows.length) {
        referrer = found.rows[0].id;
      }
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const uid =
      "SKY" +
      Date.now().toString().slice(-8) +
      Math.floor(Math.random() * 90 + 10);

    const code =
      "SKY" +
      Math.random().toString(36).slice(2, 9).toUpperCase();

    const result = await pool.query(
      `INSERT INTO users
       (uid, username, name, phone, password_hash, referral_code, referred_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING id,uid,username,name,phone,referral_code,balance,status`,
      [uid, phone, name, phone, passwordHash, code, referrer]
    );

    const user = result.rows[0];

    const token = makeToken({
      id: user.id,
      role: "user"
    });

    res.status(201).json({
      message: "Registration successful.",
      token,
      user
    });

  } catch (error) {
    console.error("Registration:", error);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "This phone number or account is already registered."
      });
    }

    res.status(500).json({
      error: "Registration failed. Please try again."
    });
  }
});

// USER LOGIN
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const phone = normalizePhone(req.body.phone);
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE phone=$1",
      [phone]
    );

    const user = result.rows[0];

    if (
      !user ||
      !user.password_hash ||
      !(await bcrypt.compare(password, user.password_hash))
    ) {
      return res.status(401).json({
        error: "Incorrect phone number or password."
      });
    }

    if (user.status !== "active") {
      return res.status(403).json({
        error: "This account is not active."
      });
    }

    const token = makeToken({
      id: user.id,
      role: "user"
    });

    delete user.password_hash;
    delete user.password;

    res.json({
      message: "Login successful.",
      token,
      user
    });

  } catch (error) {
    console.error("Login:", error);

    res.status(500).json({
      error: "Login failed."
    });
  }
});

// PUBLIC PRODUCTS
app.get("/api/products", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,name,price,duration_days,daily_estimate,
       image_url,description
       FROM products
       WHERE active=TRUE
       ORDER BY id`
    );

    res.json({
      products: result.rows
    });

  } catch (error) {
    console.error("Products:", error);

    res.status(500).json({
      error: "Could not load products."
    });
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
       FROM users u
       WHERE u.id=$1`,
      [req.userId]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    res.json({
      user: result.rows[0]
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load profile."
    });
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
      return res.status(400).json({
        error: "Choose bKash or Nagad."
      });
    }

    if (!validAmount(amount) || amount > 1000000) {
      return res.status(400).json({
        error: "Enter a valid amount."
      });
    }

    if (!/^\+?[0-9]{8,16}$/.test(sender)) {
      return res.status(400).json({
        error: "Enter a valid sender number."
      });
    }

    if (transactionId.length < 4 || transactionId.length > 120) {
      return res.status(400).json({
        error: "Enter a valid transaction ID."
      });
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

    res.status(500).json({
      error: "Could not submit deposit request."
    });
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
      return res.status(400).json({
        error: "Choose bKash or Nagad."
      });
    }

    if (!validAmount(amount) || amount > 1000000) {
      return res.status(400).json({
        error: "Enter a valid amount."
      });
    }

    if (!/^\+?[0-9]{8,16}$/.test(account)) {
      return res.status(400).json({
        error: "Enter a valid account number."
      });
    }

    await client.query("BEGIN");
    started = true;

    const user = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [req.userId]
    );

    if (!user.rows.length) {
      throw new Error("User not found.");
    }

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

    res.status(400).json({
      error: error.message || "Could not submit request."
    });

  } finally {
    client.release();
  }
});

// ACTIVATE PRODUCT
app.post("/api/activate", userAuth, async (req, res) => {
  const client = await pool.connect();
  let started = false;

  try {
    const productId = Number(req.body.productId);

    if (!Number.isInteger(productId) || productId < 1) {
      return res.status(400).json({
        error: "Invalid product."
      });
    }

    await client.query("BEGIN");
    started = true;

    const product = await client.query(
      "SELECT * FROM products WHERE id=$1 AND active=TRUE",
      [productId]
    );

    if (!product.rows.length) {
      throw new Error("Product is not available.");
    }

    const p = product.rows[0];
    const price = Number(p.price);

    if (price <= 0) {
      throw new Error("This product has not been configured by admin.");
    }

    const user = await client.query(
      "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
      [req.userId]
    );

    if (!user.rows.length || Number(user.rows[0].balance) < price) {
      throw new Error("Insufficient wallet balance.");
    }

    await client.query(
      "UPDATE users SET balance=balance-$1 WHERE id=$2",
      [price, req.userId]
    );

    await client.query(
      `INSERT INTO plans
       (user_id,product_id,product_name,price,daily_estimate,duration_days)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        req.userId,
        p.id,
        p.name,
        price,
        p.daily_estimate,
        p.duration_days
      ]
    );

    await client.query("COMMIT");
    started = false;

    res.json({
      message: "Product activated successfully."
    });

  } catch (error) {
    if (started) await client.query("ROLLBACK");

    res.status(400).json({
      error: error.message || "Activation failed."
    });

  } finally {
    client.release();
  }
});

// USER ORDERS AND TRANSACTIONS
app.get("/api/my-orders", userAuth, async (req, res) => {
  try {
    const [plans, transactions] = await Promise.all([
      pool.query(
        `SELECT id,product_name,price,daily_estimate,
         duration_days,status,created_at
         FROM plans
         WHERE user_id=$1
         ORDER BY id DESC`,
        [req.userId]
      ),

      pool.query(
        `SELECT id,type,method,amount,status,created_at
         FROM payment_requests
         WHERE user_id=$1
         ORDER BY id DESC`,
        [req.userId]
      )
    ]);

    res.json({
      plans: plans.rows,
      transactions: transactions.rows
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load order history."
    });
  }
});

// TEAM / REFERRALS
app.get("/api/team", userAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT COUNT(*) FROM users WHERE referred_by=$1",
      [req.userId]
    );

    res.json({
      count: Number(result.rows[0].count)
    });

  } catch (error) {
    res.status(500).json({
      error: "Could not load team."
    });
  }
});

// AI CHAT HISTORY
app.get("/api/chat/history", userAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,role,content,created_at
       FROM (
         SELECT id,role,content,created_at
         FROM chat_messages
         WHERE user_id=$1
         ORDER BY id DESC
         LIMIT 50
       ) recent
       ORDER BY id ASC`,
      [req.userId]
    );

    res.json({
      messages: result.rows
    });

  } catch (error) {
    console.error("Chat history:", error);

    res.status(500).json({
      error: "Could not load chat history."
    });
  }
});

// GEMINI AI LIVE CHAT
app.post("/api/chat", userAuth, chatLimiter, async (req, res) => {
  try {
    const message = String(req.body.message || "").trim();

    if (!message || message.length > 2000) {
      return res.status(400).json({
        error: "Message must be between 1 and 2000 characters."
      });
    }

    const geminiApiKey = process.env.GEMINI_API_KEY;

    if (!geminiApiKey) {
      return res.status(503).json({
        error: "AI service is not configured. Please contact support."
      });
    }

    const userResult = await pool.query(
      `SELECT id,uid,name,phone
       FROM users
       WHERE id=$1`,
      [req.userId]
    );

    if (!userResult.rows.length) {
      return res.status(404).json({
        error: "User not found."
      });
    }

    const user = userResult.rows[0];

    await pool.query(
      `INSERT INTO chat_messages (user_id,role,content)
       VALUES ($1,'user',$2)`,
      [req.userId, message]
    );

    const historyResult = await pool.query(
      `SELECT role,content
       FROM (
         SELECT role,content,id
         FROM chat_messages
         WHERE user_id=$1
         ORDER BY id DESC
         LIMIT 12
       ) recent
       ORDER BY id ASC`,
      [req.userId]
    );

    const instructions = `
You are SKYPAY's helpful customer support AI.

Reply in the same language as the user.
If the user writes Bengali, reply in simple Bengali.

Help with registration, login, profile, products,
deposit requests, withdrawal requests and website navigation.

Never ask for passwords, OTPs, API keys, card details
or secret tokens.

Never claim a deposit or withdrawal has been approved
unless the system actually confirms it.

Never claim you have changed a user's account.

Do not promise guaranteed profit, investment returns
or earnings. Do not describe any product as risk-free.

For private account matters that you cannot verify,
ask the user to contact a human administrator.

If you cannot confidently solve the problem, or the user
asks for a human administrator, set needs_human to true.

Return ONLY valid JSON in this exact format:
{
  "reply": "Your helpful answer to the user",
  "needs_human": false,
  "reason": ""
}

If human help is required, set needs_human to true
and give a short reason in the reason field.
Keep the reply polite and helpful.
`;

    const contents = historyResult.rows.map(item => ({
      role: item.role === "assistant" ? "model" : "user",
      parts: [{ text: item.content }]
    }));

    let aiResponse = "";

    try {
      const model = process.env.GEMINI_MODEL || "gemini-3.8-flash";

      const response = await fetch(
        `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-goog-api-key": geminiApiKey
          },
          body: JSON.stringify({
            systemInstruction: {
              parts: [{ text: instructions }]
            },
            contents,
            generationConfig: {
              maxOutputTokens: 700,
              responseMimeType: "application/json"
            }
          })
        }
      );

      const data = await response.json();

      if (!response.ok) {
        console.error("Gemini API error:", data);
        throw new Error(
          data.error?.message || "Gemini service request failed."
        );
      }

      aiResponse =
        data.candidates?.[0]?.content?.parts
          ?.map(part => part.text || "")
          .join("") || "";

      if (!aiResponse) {
        throw new Error("Gemini returned an empty response.");
      }

    } catch (aiError) {
      console.error("Gemini chat error:", aiError.message);

      await pool.query(
        `INSERT INTO chat_escalations (user_id,message,reason)
         VALUES ($1,$2,$3)`,
        [req.userId, message, "Gemini AI service error"]
      );

      await sendTelegramMessage(
        "SKYPAY URGENT SUPPORT\n\n" +
        "Gemini AI service could not respond.\n" +
        "User: " + user.name + "\n" +
        "UID: " + user.uid + "\n" +
        "Phone: " + user.phone + "\n" +
        "Message: " + message
      );

      return res.status(503).json({
        error: "AI is temporarily unavailable. Your support request has been sent to the administrator."
      });
    }

    let parsed;

    try {
      const cleaned = aiResponse
        .replace(/^```json/i, "")
        .replace(/^```/i, "")
        .replace(/```$/i, "")
        .trim();

      parsed = JSON.parse(cleaned);
    } catch {
      parsed = {
        reply: aiResponse,
        needs_human: false,
        reason: ""
      };
    }

    const reply = String(
      parsed.reply || "দুঃখিত, আমি উত্তর দিতে পারছি না।"
    ).slice(0, 5000);

    const needsHuman = parsed.needs_human === true;
    const reason = String(
      parsed.reason || "Human support requested."
    ).slice(0, 500);

    await pool.query(
      `INSERT INTO chat_messages (user_id,role,content)
       VALUES ($1,'assistant',$2)`,
      [req.userId, reply]
    );

    let supportSent = false;

    if (needsHuman) {
      await pool.query(
        `INSERT INTO chat_escalations (user_id,message,reason)
         VALUES ($1,$2,$3)`,
        [req.userId, message, reason]
      );

      supportSent = await sendTelegramMessage(
        "SKYPAY HUMAN SUPPORT NEEDED\n\n" +
        "User: " + user.name + "\n" +
        "UID: " + user.uid + "\n" +
        "Phone: " + user.phone + "\n\n" +
        "User message:\n" + message + "\n\n" +
        "AI reason:\n" + reason
      );
    }

    res.json({
      reply,
      needsHuman,
      supportSent
    });

  } catch (error) {
    console.error("Chat endpoint:", error);

    res.status(500).json({
      error: "Could not process your chat message."
    });
  }
});

// ADMIN LOGIN
app.post("/api/admin/login", adminLimiter, async (req, res) => {
  try {
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");

    const configuredEmail = process.env.ADMIN_EMAIL
      .trim()
      .toLowerCase();

    if (email !== configuredEmail) {
      return res.status(401).json({
        error: "Invalid admin credentials."
      });
    }

    const valid = await bcrypt.compare(
      password,
      process.env.ADMIN_PASSWORD_HASH
    );

    if (!valid) {
      return res.status(401).json({
        error: "Invalid admin credentials."
      });
    }

    const token = makeToken({
      role: "admin"
    });

    res.json({
      message: "Admin login successful.",
      token
    });

  } catch (error) {
    console.error("Admin login:", error);

    res.status(500).json({
      error: "Admin login failed."
    });
  }
});

// ADMIN USERS
app.get("/api/admin/users", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id,uid,username,name,phone,balance,total_deposit,
       total_withdraw,status,created_at
       FROM users
       ORDER BY id DESC`
    );

    res.json({
      users: result.rows
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load users."
    });
  }
});

// ADMIN PRODUCTS
app.get("/api/admin/products", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "SELECT * FROM products ORDER BY id DESC"
    );

    res.json({
      products: result.rows
    });

  } catch (error) {
    res.status(500).json({
      error: "Could not load products."
    });
  }
});

// ADD PRODUCT
app.post("/api/admin/products", adminAuth, async (req, res) => {
  try {
    const {
      name,
      price,
      duration_days,
      daily_estimate,
      image_url,
      description,
      active
    } = req.body;

    if (
      !String(name || "").trim() ||
      !validAmountOrZero(price) ||
      !Number.isInteger(Number(duration_days)) ||
      Number(duration_days) < 1 ||
      !validAmountOrZero(daily_estimate)
    ) {
      return res.status(400).json({
        error: "Check product name, price, duration and estimate."
      });
    }

    const result = await pool.query(
      `INSERT INTO products
       (name,price,duration_days,daily_estimate,image_url,description,active)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       RETURNING *`,
      [
        String(name).trim(),
        Number(price),
        Number(duration_days),
        Number(daily_estimate),
        String(image_url || ""),
        String(description || ""),
        active !== false
      ]
    );

    res.status(201).json({
      product: result.rows[0]
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not create product."
    });
  }
});

// UPDATE PRODUCT
app.put("/api/admin/products/:id", adminAuth, async (req, res) => {
  try {
    const {
      name,
      price,
      duration_days,
      daily_estimate,
      image_url,
      description,
      active
    } = req.body;

    if (
      !String(name || "").trim() ||
      !validAmountOrZero(price) ||
      !Number.isInteger(Number(duration_days)) ||
      Number(duration_days) < 1 ||
      !validAmountOrZero(daily_estimate)
    ) {
      return res.status(400).json({
        error: "Invalid product information."
      });
    }

    const result = await pool.query(
      `UPDATE products
       SET name=$1,price=$2,duration_days=$3,daily_estimate=$4,
       image_url=$5,description=$6,active=$7
       WHERE id=$8
       RETURNING *`,
      [
        String(name).trim(),
        Number(price),
        Number(duration_days),
        Number(daily_estimate),
        String(image_url || ""),
        String(description || ""),
        active === true,
        Number(req.params.id)
      ]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Product not found."
      });
    }

    res.json({
      product: result.rows[0]
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not update product."
    });
  }
});

// DELETE PRODUCT
app.delete("/api/admin/products/:id", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      "DELETE FROM products WHERE id=$1 RETURNING id",
      [Number(req.params.id)]
    );

    if (!result.rows.length) {
      return res.status(404).json({
        error: "Product not found."
      });
    }

    res.json({
      message: "Product deleted."
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not delete product."
    });
  }
});

// ADMIN PAYMENT REQUESTS
app.get("/api/admin/requests", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT r.*,u.name AS user_name,u.uid AS user_uid
       FROM payment_requests r
       JOIN users u ON u.id=r.user_id
       ORDER BY r.id DESC`
    );

    res.json({
      requests: result.rows
    });

  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Could not load requests."
    });
  }
});

// APPROVE OR REJECT PAYMENT REQUESTS
app.patch("/api/admin/requests/:id", adminAuth, async (req, res) => {
  const client = await pool.connect();
  let started = false;

  try {
    const id = Number(req.params.id);
    const status = String(req.body.status || "");

    if (
      !Number.isInteger(id) ||
      !["approved", "rejected"].includes(status)
    ) {
      return res.status(400).json({
        error: "Invalid request."
      });
    }

    await client.query("BEGIN");
    started = true;

    const found = await client.query(
      "SELECT * FROM payment_requests WHERE id=$1 FOR UPDATE",
      [id]
    );

    if (!found.rows.length) {
      throw new Error("Request not found.");
    }

    const request = found.rows[0];

    if (request.status !== "pending") {
      throw new Error("This request was already reviewed.");
    }

    if (status === "approved" && request.type === "deposit") {
      await client.query(
        `UPDATE users
         SET balance=balance+$1,
             total_deposit=total_deposit+$1
         WHERE id=$2`,
        [request.amount, request.user_id]
      );
    }

    if (status === "approved" && request.type === "withdraw") {
      const user = await client.query(
        "SELECT balance FROM users WHERE id=$1 FOR UPDATE",
        [request.user_id]
      );

      if (
        !user.rows.length ||
        Number(user.rows[0].balance) < Number(request.amount)
      ) {
        throw new Error("User has insufficient balance.");
      }

      await client.query(
        `UPDATE users
         SET balance=balance-$1,
             total_withdraw=total_withdraw+$1
         WHERE id=$2`,
        [request.amount, request.user_id]
      );
    }

    await client.query(
      `UPDATE payment_requests
       SET status=$1,reviewed_at=NOW()
       WHERE id=$2`,
      [status, id]
    );

    await client.query("COMMIT");
    started = false;

    res.json({
      message: "Request " + status + " successfully."
    });

  } catch (error) {
    if (started) await client.query("ROLLBACK");

    console.error("Payment review:", error);

    res.status(400).json({
      error: error.message || "Could not review request."
    });

  } finally {
    client.release();
  }
});

// ADMIN CHAT SUPPORT REQUESTS
app.get("/api/admin/chat-escalations", adminAuth, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT e.id,e.user_id,e.message,e.reason,e.status,e.created_at,
              u.name AS user_name,u.uid AS user_uid,u.phone AS user_phone
       FROM chat_escalations e
       JOIN users u ON u.id=e.user_id
       ORDER BY e.id DESC
       LIMIT 100`
    );

    res.json({
      escalations: result.rows
    });

  } catch (error) {
    console.error("Admin chat escalations:", error);

    res.status(500).json({
      error: "Could not load support requests."
    });
  }
});

// NOT FOUND
app.use((req, res) => {
  res.status(404).json({
    error: "API route not found."
  });
});

// GENERAL ERROR HANDLER
app.use((error, req, res, next) => {
  console.error("Server error:", error);

  res.status(500).json({
    error: "Internal server error."
  });
});

// START SERVER
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
