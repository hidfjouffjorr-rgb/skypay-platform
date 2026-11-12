const express = require("express");
const router = express.Router();
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

async function createTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS managed_apps (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      size TEXT DEFAULT '',
      download_url TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )
  `);
}

function adminOnly(req, res, next) {
  try {
    const header = req.headers.authorization || "";
    const token = header.replace(/^Bearer\s+/i, "");
    if (!token) {
      return res.status(401).json({ error: "Login required" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin") {
      return res.status(403).json({ error: "Admin only" });
    }

    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Public app list
router.get("/apps", async (req, res) => {
  try {
    await createTable();
    const result = await pool.query(
      "SELECT id, name, version, size, download_url FROM managed_apps ORDER BY id DESC"
    );
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: "Could not load apps" });
  }
});

// Add app
router.post("/admin/apps", adminOnly, async (req, res) => {
  try {
    await createTable();
    const { name, version, size, download_url } = req.body;

    if (!name || !version || !download_url) {
      return res.status(400).json({
        error: "Name, version and download URL are required"
      });
    }

    const result = await pool.query(
      `INSERT INTO managed_apps (name, version, size, download_url)
       VALUES ($1, $2, $3, $4)
       RETURNING *`,
      [name, version, size || "", download_url]
    );

    res.status(201).json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Could not add app" });
  }
});

// Edit app
router.put("/admin/apps/:id", adminOnly, async (req, res) => {
  try {
    await createTable();
    const { name, version, size, download_url } = req.body;

    const result = await pool.query(
      `UPDATE managed_apps
       SET name=$1, version=$2, size=$3, download_url=$4
       WHERE id=$5 RETURNING *`,
      [name, version, size || "", download_url, req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "App not found" });
    }

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: "Could not update app" });
  }
});

// Delete app
router.delete("/admin/apps/:id", adminOnly, async (req, res) => {
  try {
    await createTable();
    const result = await pool.query(
      "DELETE FROM managed_apps WHERE id=$1 RETURNING id",
      [req.params.id]
    );

    if (!result.rowCount) {
      return res.status(404).json({ error: "App not found" });
    }

    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: "Could not delete app" });
  }
});

module.exports = router;
