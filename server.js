const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL &&
       !process.env.DATABASE_URL.includes("localhost")
    ? { rejectUnauthorized: false }
    : false
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));

app.use("/api/", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 150
}));

function asyncRoute(fn) {
  return (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);
}

function makeToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  if (!token) {
    return res.status(401).json({ error: "লগইন প্রয়োজন" });
  }

  try {
    req.auth = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "আবার লগইন করুন" });
  }
}

function adminOnly(req, res, next) {
  if (req.auth?.role !== "admin") {
    return res.status(403).json({ error: "Admin only" });
  }
  next();
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      uid TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT DEFAULT '',
      password_hash TEXT NOT NULL,
      referral_code TEXT UNIQUE NOT NULL,
      referred_by TEXT,
      wallet NUMERIC(14,2) DEFAULT 0,
      role TEXT DEFAULT 'user',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS products (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      price NUMERIC(14,2) DEFAULT 0,
      duration_days INTEGER DEFAULT 30,
      daily_estimate NUMERIC(14,2) DEFAULT 0,
      image_url TEXT DEFAULT '',
      description TEXT DEFAULT '',
      active BOOLEAN DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS requests (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      type TEXT NOT NULL,
      amount NUMERIC(14,2) NOT NULL,
      method TEXT DEFAULT '',
      sender_number TEXT DEFAULT '',
      transaction_id TEXT DEFAULT '',
      status TEXT DEFAULT 'pending',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS active_plans (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id),
      product_id BIGINT REFERENCES products(id),
      product_name TEXT NOT NULL,
      price NUMERIC(14,2) NOT NULL,
      daily_estimate NUMERIC(14,2) NOT NULL,
      duration_days INTEGER NOT NULL,
      activated_at TIMESTAMPTZ DEFAULT NOW(),
      status TEXT DEFAULT 'active'
    );
  `);

  const count = await pool.query(
    "SELECT COUNT(*)::int AS n FROM products"
  );

  if (count.rows[0].n === 0) {
    const products = [
      ["Starter 1",500,30,15],
      ["Starter 2",1000,30,30],
      ["Starter 3",1500,30,45],
      ["Silver 1",2000,30,60],
      ["Silver 2",3000,30,90],
      ["Gold 1",5000,30,150],
      ["Gold 2",7500,30,225],
      ["Premium 1",10000,30,300],
      ["Plan 09",1200,30,36],
      ["Plan 10",1800,30,54],
      ["Plan 11",2500,30,75],
      ["Plan 12",3500,30,105],
      ["Plan 13",4500,30,135],
      ["Plan 14",6000,30,180],
      ["Plan 15",8000,30,240]
    ];

    for (const p of products) {
      await pool.query(
        `INSERT INTO products
         (name,price,duration_days,daily_estimate)
         VALUES($1,$2,$3,$4)`,
        p
      );
    }
  }
}

app.get("/api/health", (req, res) => {
  res.json({ ok: true, service: "SKYPAY API" });
});

// USER REGISTRATION
app.post("/api/register", asyncRoute(async (req, res) => {
  const { name, email, phone = "", password, referralCode = "" } = req.body;

  if (!name || !email || !password || password.length < 6) {
    return res.status(400).json({
      error: "নাম, ইমেইল ও কমপক্ষে ৬ অক্ষরের পাসওয়ার্ড দিন"
    });
  }

  const uid = "SKY" + Date.now().toString().slice(-8);
  const referral = "SKY" +
    Math.random().toString(36).slice(2, 8).toUpperCase();

  const hash = await bcrypt.hash(password, 12);

  try {
    const result = await pool.query(
      `INSERT INTO users
       (uid,name,email,phone,password_hash,referral_code,referred_by)
       VALUES($1,$2,$3,$4,$5,$6,$7)
       RETURNING id,uid,name,email,phone,referral_code,wallet,role`,
      [
        uid,
        name.trim(),
        email.trim().toLowerCase(),
        phone,
        hash,
        referral,
        referralCode || null
      ]
    );

    const user = result.rows[0];

    res.status(201).json({
      token: makeToken(user),
      user
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({
        error: "এই ইমেইল দিয়ে অ্যাকাউন্ট আছে"
      });
    }
    throw error;
  }
}));

// USER LOGIN
app.post("/api/login", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  const result = await pool.query(
    "SELECT * FROM users WHERE email=$1",
    [email]
  );

  const user = result.rows[0];

  if (!user || !(await bcrypt.compare(password, user.password_hash))) {
    return res.status(401).json({
      error: "ইমেইল অথবা পাসওয়ার্ড সঠিক নয়"
    });
  }

  const safeUser = {
    id: user.id,
    uid: user.uid,
    name: user.name,
    email: user.email,
    phone: user.phone,
    referral_code: user.referral_code,
    wallet: user.wallet,
    role: user.role
  };

  res.json({
    token: makeToken(safeUser),
    user: safeUser
  });
}));

// USER PROFILE
app.get("/api/me", auth, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id,uid,name,email,phone,referral_code,
     wallet,role,created_at FROM users WHERE id=$1`,
    [req.auth.id]
  );

  if (!result.rows[0]) {
    return res.status(404).json({ error: "ইউজার পাওয়া যায়নি" });
  }

  res.json({ user: result.rows[0] });
}));

// PRODUCTS
app.get("/api/products", asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM products WHERE active=TRUE ORDER BY id"
  );

  res.json({ products: result.rows });
}));

// USER ACTIVE PLANS
app.get("/api/plans", auth, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM active_plans WHERE user_id=$1 ORDER BY activated_at DESC",
    [req.auth.id]
  );

  res.json({ plans: result.rows });
}));

// ACTIVATE PRODUCT
app.post("/api/plans/activate", auth, asyncRoute(async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const productResult = await client.query(
      "SELECT * FROM products WHERE id=$1 AND active=TRUE",
      [Number(req.body.productId)]
    );

    const product = productResult.rows[0];

    if (!product) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "পণ্য পাওয়া যায়নি" });
    }

    const userResult = await client.query(
      "SELECT * FROM users WHERE id=$1 FOR UPDATE",
      [req.auth.id]
    );

    const user = userResult.rows[0];

    if (Number(user.wallet) < Number(product.price)) {
      await client.query("ROLLBACK");
      return res.status(400).json({
        error: "ওয়ালেটে পর্যাপ্ত ব্যালেন্স নেই"
      });
    }

    await client.query(
      "UPDATE users SET wallet=wallet-$1 WHERE id=$2",
      [product.price, req.auth.id]
    );

    const plan = await client.query(
      `INSERT INTO active_plans
       (user_id,product_id,product_name,price,daily_estimate,duration_days)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
      [
        req.auth.id,
        product.id,
        product.name,
        product.price,
        product.daily_estimate,
        product.duration_days
      ]
    );

    await client.query("COMMIT");

    res.status(201).json({ plan: plan.rows[0] });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

// DEPOSIT AND WITHDRAW REQUEST
app.post("/api/requests", auth, asyncRoute(async (req, res) => {
  const {
    type,
    amount,
    method = "",
    senderNumber = "",
    transactionId = ""
  } = req.body;

  const value = Number(amount);

  if (!["deposit", "withdraw"].includes(type) ||
      !Number.isFinite(value) || value <= 0) {
    return res.status(400).json({ error: "সঠিক পরিমাণ দিন" });
  }

  if (type === "deposit" &&
      (!method || !transactionId || !senderNumber)) {
    return res.status(400).json({
      error: "পেমেন্ট তথ্য সম্পূর্ণ দিন"
    });
  }

  if (type === "withdraw") {
    const user = await pool.query(
      "SELECT wallet FROM users WHERE id=$1",
      [req.auth.id]
    );

    if (Number(user.rows[0].wallet) < value) {
      return res.status(400).json({
        error: "ওয়ালেটে পর্যাপ্ত ব্যালেন্স নেই"
      });
    }
  }

  const result = await pool.query(
    `INSERT INTO requests
     (user_id,type,amount,method,sender_number,transaction_id)
     VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
    [
      req.auth.id,
      type,
      value,
      method,
      senderNumber,
      transactionId
    ]
  );

  res.status(201).json({ request: result.rows[0] });
}));

// MY REQUESTS
app.get("/api/requests/mine", auth, asyncRoute(async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM requests WHERE user_id=$1 ORDER BY created_at DESC",
    [req.auth.id]
  );

  res.json({ requests: result.rows });
}));

// ADMIN LOGIN
app.post("/api/admin/login", asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  const adminEmail = String(process.env.ADMIN_EMAIL || "")
    .trim().toLowerCase();

  const passwordHash = process.env.ADMIN_PASSWORD_HASH || "";

  if (!adminEmail || !passwordHash ||
      email !== adminEmail ||
      !(await bcrypt.compare(password, passwordHash))) {
    return res.status(401).json({
      error: "অ্যাডমিন লগইন তথ্য সঠিক নয়"
    });
  }

  const admin = { id: "admin", role: "admin" };

  res.json({
    token: makeToken(admin),
    user: { email, role: "admin" }
  });
}));

// ADMIN STATS
app.get("/api/admin/stats", auth, adminOnly, asyncRoute(async (req, res) => {
  const users = await pool.query("SELECT COUNT(*)::int AS n FROM users");
  const products = await pool.query("SELECT COUNT(*)::int AS n FROM products");
  const pending = await pool.query(
    "SELECT COUNT(*)::int AS n FROM requests WHERE status='pending'"
  );

  res.json({
    users: users.rows[0].n,
    products: products.rows[0].n,
    pending: pending.rows[0].n
  });
}));

// ADMIN USERS
app.get("/api/admin/users", auth, adminOnly, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT id,uid,name,email,phone,wallet,created_at
     FROM users WHERE role='user' ORDER BY created_at DESC`
  );

  res.json({ users: result.rows });
}));

// ADMIN REQUESTS
app.get("/api/admin/requests", auth, adminOnly, asyncRoute(async (req, res) => {
  const result = await pool.query(
    `SELECT r.*,u.uid,u.name,u.email
     FROM requests r JOIN users u ON u.id=r.user_id
     ORDER BY r.created_at DESC`
  );

  res.json({ requests: result.rows });
}));

// APPROVE OR REJECT REQUEST
app.post("/api/admin/requests/:id/decision", auth, adminOnly,
asyncRoute(async (req, res) => {
  const decision = req.body.decision;

  if (!["approved", "rejected"].includes(decision)) {
    return res.status(400).json({ error: "সঠিক সিদ্ধান্ত দিন" });
  }

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(
      "SELECT * FROM requests WHERE id=$1 FOR UPDATE",
      [req.params.id]
    );

    const request = result.rows[0];

    if (!request || request.status !== "pending") {
      await client.query("ROLLBACK");
      return res.status(409).json({
        error: "রিকোয়েস্ট পাওয়া যায়নি অথবা আগেই প্রসেস হয়েছে"
      });
    }

    if (decision === "approved") {
      if (request.type === "deposit") {
        await client.query(
          "UPDATE users SET wallet=wallet+$1 WHERE id=$2",
          [request.amount, request.user_id]
        );
      } else {
        const user = await client.query(
          "SELECT wallet FROM users WHERE id=$1 FOR UPDATE",
          [request.user_id]
        );

        if (Number(user.rows[0].wallet) < Number(request.amount)) {
          await client.query("ROLLBACK");
          return res.status(400).json({
            error: "পর্যাপ্ত ব্যালেন্স নেই"
          });
        }

        await client.query(
          "UPDATE users SET wallet=wallet-$1 WHERE id=$2",
          [request.amount, request.user_id]
        );
      }
    }

    await client.query(
      "UPDATE requests SET status=$1 WHERE id=$2",
      [decision, request.id]
    );

    await client.query("COMMIT");

    res.json({ success: true, status: decision });
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}));

// ADD PRODUCT
app.post("/api/admin/products", auth, adminOnly,
asyncRoute(async (req, res) => {
  const {
    name, price, durationDays,
    dailyEstimate, imageUrl = "",
    description = "", active = true
  } = req.body;

  if (!name || Number(price) < 0 ||
      Number(durationDays) < 1 ||
      Number(dailyEstimate) < 0) {
    return res.status(400).json({
      error: "পণ্যের তথ্য সঠিকভাবে দিন"
    });
  }

  const result = await pool.query(
    `INSERT INTO products
     (name,price,duration_days,daily_estimate,image_url,description,active)
     VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING *`,
    [
      name, price, durationDays,
      dailyEstimate, imageUrl,
      description, Boolean(active)
    ]
  );

  res.status(201).json({ product: result.rows[0] });
}));

// EDIT PRODUCT
app.put("/api/admin/products/:id", auth, adminOnly,
asyncRoute(async (req, res) => {
  const {
    name, price, durationDays,
    dailyEstimate, imageUrl = "",
    description = "", active = true
  } = req.body;

  const result = await pool.query(
    `UPDATE products SET
     name=$1,price=$2,duration_days=$3,
     daily_estimate=$4,image_url=$5,
     description=$6,active=$7
     WHERE id=$8 RETURNING *`,
    [
      name, price, durationDays,
      dailyEstimate, imageUrl,
      description, Boolean(active),
      req.params.id
    ]
  );

  if (!result.rows[0]) {
    return res.status(404).json({ error: "পণ্য পাওয়া যায়নি" });
  }

  res.json({ product: result.rows[0] });
}));

// DELETE PRODUCT
app.delete("/api/admin/products/:id", auth, adminOnly,
asyncRoute(async (req, res) => {
  const result = await pool.query(
    "DELETE FROM products WHERE id=$1 RETURNING id",
    [req.params.id]
  );

  if (!result.rows[0]) {
    return res.status(404).json({ error: "পণ্য পাওয়া যায়নি" });
  }

  res.json({ success: true });
}));

app.use((error, req, res, next) => {
  console.error(error);
  res.status(500).json({ error: "সার্ভারে সমস্যা হয়েছে" });
});

initDb()
  .then(() => {
    app.listen(PORT, () => {
      console.log("SKYPAY server running on port " + PORT);
    });
  })
  .catch(error => {
    console.error("Database initialization failed:", error);
    process.exit(1);
  });
