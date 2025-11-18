// ==================== IMPORTS ====================
const express = require("express");
const mysql = require("mysql");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const path = require("path");

const app = express();
const PORT = 3000;

// ==================== MIDDLEWARE ====================
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static frontend files (HTML, CSS, JS) from the "public" folder
app.use(express.static(path.join(__dirname, "public")));

// ==================== MYSQL CONNECTION ====================
const db = mysql.createConnection({
  host: "localhost",      // MySQL host
  port: 3306,             // default port
  user: "root",           // default MySQL user (XAMPP/WAMP)
  password: "",           // blank for local setup
  database: "login_db",   // database you created in Workbench
});

db.connect((err) => {
  if (err) {
    console.error("❌ Database connection failed:", err.message);
  } else {
    console.log("✅ Connected to MySQL: login_db");
  }
});

// ==================== ROUTES ====================

// -------- REGISTER (POST /register) --------
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validate required fields
    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ success: false, message: "All fields are required" });
    }

    // Hash password for security
    const password_hash = await bcrypt.hash(password, 10);

    // Insert user into database
    db.query(
      "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
      [name, email, password_hash],
      (err) => {
        if (err) {
          if (err.code === "ER_DUP_ENTRY") {
            return res.json({
              success: false,
              message: "Email already registered",
            });
          }
          console.error("❌ DB Insert Error:", err);
          return res
            .status(500)
            .json({ success: false, message: "Database error" });
        }
        res.json({ success: true, message: "Registration successful" });
      }
    );
  } catch (e) {
    console.error("❌ Server Error:", e);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

// -------- LOGIN (POST /login) --------
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required" });
  }

  // Check if user exists
  db.query("SELECT * FROM users WHERE email = ?", [email], async (err, rows) => {
    if (err) {
      console.error("❌ DB Query Error:", err);
      return res
        .status(500)
        .json({ success: false, message: "Database error" });
    }

    if (rows.length === 0) {
      return res.json({ success: false, message: "User not found" });
    }

    const user = rows[0];

    // Compare entered password with stored hash
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) {
      return res.json({ success: false, message: "Invalid credentials" });
    }

    // Successful login
    res.json({
      success: true,
      message: "Login successful",
      name: user.name,
    });
  });
});

// ==================== START SERVER ====================

// ❌ Removed wildcard route (* or /*) — not needed in Express 5
// ✅ Static files (index.html, register.html, etc.) are automatically served
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
