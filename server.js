
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const neo4j = require("neo4j-driver");
const crypto = require("crypto");
const { promisify } = require("util");

const scryptAsync = promisify(crypto.scrypt);

const app = express();

// ==========================================
// CORS CONFIGURATION
// ==========================================

const allowedOrigins = [
  "http://localhost:3000",
  "http://localhost:5000",
  "http://localhost:8080",
  process.env.FRONTEND_URL,
].filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin || allowedOrigins.includes(origin)) {
        return callback(null, true);
      }

      console.log("Blocked CORS origin:", origin);
      return callback(new Error("Origin not allowed by CORS"));
    },
  })
);

app.use(express.json());

// ==========================================
// NEO4J CONNECTION
// ==========================================

if (
  !process.env.NEO4J_URI ||
  !process.env.NEO4J_USERNAME ||
  !process.env.NEO4J_PASSWORD
) {
  console.error("ERROR: Missing Neo4j environment variables.");
  process.exit(1);
}

const driver = neo4j.driver(
  process.env.NEO4J_URI,
  neo4j.auth.basic(
    process.env.NEO4J_USERNAME,
    process.env.NEO4J_PASSWORD
  )
);

// ==========================================
// REPORT CATEGORY LABELS
// ==========================================

const categoryLabels = {
  Flood: "Flood",
  Fire: "Fire",
  Earthquake: "Earthquake",
  Landslide: "Landslide",
  Medical: "Medical",
  Other: "Other",
};

// ==========================================
// HOME / TEST API
// ==========================================

app.get("/", (req, res) => {
  res.json({
    success: true,
    message: "AlertAgos API is running!",
  });
});

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/health", async (req, res) => {
  try {
    await driver.verifyConnectivity();

    return res.json({
      success: true,
      status: "success",
      database: "Neo4j connected",
    });
  } catch (error) {
    console.error("Neo4j connection error:", error.message);

    return res.status(500).json({
      success: false,
      status: "error",
      database: "Connection failed",
    });
  }
});

// ==========================================
// RESIDENT SIGNUP
// ==========================================

app.post("/api/signup", async (req, res) => {
  const { name, email, phone, password } = req.body;

  if (!name || !email || !phone || !password) {
    return res.status(400).json({
      success: false,
      message: "Please complete all signup fields.",
    });
  }

  const normalizedEmail = String(email).trim().toLowerCase();

  if (
    !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(normalizedEmail) ||
    String(password).length < 6
  ) {
    return res.status(400).json({
      success: false,
      message: "Invalid email or password.",
    });
  }

  const session = driver.session();

  try {
    const existing = await session.run(
      `
      MATCH (u:User {email: $email})
      RETURN u
      LIMIT 1
      `,
      { email: normalizedEmail }
    );

    if (existing.records.length > 0) {
      return res.status(409).json({
        success: false,
        message: "Email is already registered. Please sign in.",
      });
    }

    const salt = crypto.randomBytes(16).toString("hex");

    const hash = await scryptAsync(
      String(password),
      salt,
      64
    );

    const userId = "U-" + crypto.randomUUID();

    await session.run(
      `
      CREATE (u:User {
        user_id: $user_id,
        name: $name,
        email: $email,
        phone: $phone,
        password_hash: $password_hash,
        password_salt: $password_salt,
        role: 'Resident',
        created_at: datetime()
      })
      RETURN u.user_id AS user_id
      `,
      {
        user_id: userId,
        name: String(name).trim(),
        email: normalizedEmail,
        phone: String(phone).trim(),
        password_hash: hash.toString("hex"),
        password_salt: salt,
      }
    );

    console.log("New resident registered:", normalizedEmail);

    return res.status(201).json({
      success: true,
      message: "Account created successfully!",
      user: {
        user_id: userId,
        name: String(name).trim(),
        email: normalizedEmail,
        phone: String(phone).trim(),
      },
    });
  } catch (error) {
    console.error("Signup error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to create account.",
    });
  } finally {
    await session.close();
  }
});

// ==========================================
// RESIDENT LOGIN
// ==========================================

app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({
      success: false,
      message: "Please enter your email and password.",
    });
  }

  const session = driver.session();

  try {
    const normalizedEmail = String(email).trim().toLowerCase();

    const result = await session.run(
      `
      MATCH (u:User {email: $email})
      RETURN
        u.user_id AS user_id,
        u.name AS name,
        u.email AS email,
        u.phone AS phone,
        u.password_hash AS password_hash,
        u.password_salt AS password_salt
      LIMIT 1
      `,
      { email: normalizedEmail }
    );

    if (result.records.length === 0) {
      return res.status(401).json({
        success: false,
        message: "Wrong email or password.",
      });
    }

    const record = result.records[0];

    const storedHash = record.get("password_hash");
    const salt = record.get("password_salt");

    if (
      typeof storedHash !== "string" ||
      typeof salt !== "string"
    ) {
      return res.status(401).json({
        success: false,
        message: "This account cannot be verified. Please contact support.",
      });
    }

    const suppliedHash = await scryptAsync(
      String(password),
      salt,
      64
    );

    const savedHash = Buffer.from(storedHash, "hex");

    const passwordMatches =
      savedHash.length === suppliedHash.length &&
      crypto.timingSafeEqual(savedHash, suppliedHash);

    if (!passwordMatches) {
      return res.status(401).json({
        success: false,
        message: "Wrong email or password.",
      });
    }

    console.log("Resident logged in:", normalizedEmail);

    return res.status(200).json({
      success: true,
      message: "Login successful!",
      user: {
        user_id: record.get("user_id"),
        name: record.get("name"),
        email: record.get("email"),
        phone: record.get("phone"),
      },
    });
  } catch (error) {
    console.error("Login error:", error);

    return res.status(500).json({
      success: false,
      message: "Unable to sign in. Please try again.",
    });
  } finally {
    await session.close();
  }
});

// ==========================================
// CREATE INCIDENT REPORT
// ==========================================

app.post("/api/reports", async (req, res) => {
  const {
    user_id,
    resident_name,
    type,
    zone,
    landmark,
    details,
    time,
  } = req.body;

  if (!resident_name || !type || !zone || !details) {
    return res.status(400).json({
      success: false,
      message: "Please complete all required report fields.",
    });
  }

  const categoryLabel = categoryLabels[type];

  if (!categoryLabel) {
    return res.status(400).json({
      success: false,
      message: "Invalid incident type.",
    });
  }

  const session = driver.session();

  try {
    const reportId = "R-" + crypto.randomUUID();

    const query = `
      CREATE (f:Report:${categoryLabel} {
        report_id: $report_id,
        user_id: $user_id,
        resident_name: $resident_name,
        type: $type,
        zone: $zone,
        landmark: $landmark,
        details: $details,
        status: 'Pending',
        reported_at: $reported_at,
        created_at: datetime()
      })

      WITH f
      OPTIONAL MATCH (u:User {user_id: $user_id})

      FOREACH (resident IN CASE
        WHEN u IS NULL THEN []
        ELSE [u]
      END |
        CREATE (resident)-[:SUBMITTED]->(f)
      )

      RETURN f.report_id AS report_id
    `;

    const result = await session.run(query, {
      report_id: reportId,
      user_id: user_id || "",
      resident_name: String(resident_name).trim(),
      type,
      zone: String(zone).trim(),
      landmark: String(landmark || "").trim(),
      details: String(details).trim(),
      reported_at: time || new Date().toISOString(),
    });

    if (result.records.length === 0) {
      throw new Error("Report was not created.");
    }

    console.log(`${type} report saved: ${reportId}`);

    return res.status(201).json({
      success: true,
      message: `${type} report saved successfully!`,
      report_id: reportId,
      category: type,
    });
  } catch (error) {
    console.error("Report submission error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to save incident report to Neo4j.",
    });
  } finally {
    await session.close();
  }
});

// ==========================================
// GET ALL INCIDENT REPORTS
// ==========================================

app.get("/api/reports", async (req, res) => {
  const session = driver.session();

  try {
    const result = await session.run(`
      MATCH (f:Report)

      RETURN
        f.report_id AS report_id,
        f.user_id AS user_id,
        f.resident_name AS resident_name,
        f.type AS type,
        f.zone AS zone,
        f.landmark AS landmark,
        f.details AS details,
        f.status AS status,
        f.reported_at AS reported_at,
        toString(f.created_at) AS created_at

      ORDER BY f.created_at DESC
    `);

    const reports = result.records.map((record) => ({
      report_id: record.get("report_id"),
      user_id: record.get("user_id"),
      resident_name: record.get("resident_name"),
      type: record.get("type"),
      zone: record.get("zone"),
      landmark: record.get("landmark"),
      details: record.get("details"),
      status: record.get("status"),
      reported_at: record.get("reported_at"),
      created_at: record.get("created_at"),
    }));

    return res.json({
      success: true,
      total: reports.length,
      reports,
    });
  } catch (error) {
    console.error("Retrieve reports error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to retrieve incident reports.",
    });
  } finally {
    await session.close();
  }
});

// ==========================================
// GET REPORTS BY RESIDENT
// ==========================================

app.get("/api/reports/user/:userId", async (req, res) => {
  const session = driver.session();

  try {
    const result = await session.run(
      `
      MATCH (f:Report {user_id: $user_id})

      RETURN
        f.report_id AS report_id,
        f.user_id AS user_id,
        f.resident_name AS resident_name,
        f.type AS type,
        f.zone AS zone,
        f.landmark AS landmark,
        f.details AS details,
        f.status AS status,
        f.reported_at AS reported_at,
        toString(f.created_at) AS created_at

      ORDER BY f.created_at DESC
      `,
      { user_id: req.params.userId }
    );

    const reports = result.records.map((record) => ({
      report_id: record.get("report_id"),
      user_id: record.get("user_id"),
      resident_name: record.get("resident_name"),
      type: record.get("type"),
      zone: record.get("zone"),
      landmark: record.get("landmark"),
      details: record.get("details"),
      status: record.get("status"),
      reported_at: record.get("reported_at"),
      created_at: record.get("created_at"),
    }));

    return res.json({
      success: true,
      total: reports.length,
      reports,
    });
  } catch (error) {
    console.error("User reports error:", error);

    return res.status(500).json({
      success: false,
      message: "Failed to retrieve resident reports.",
    });
  } finally {
    await session.close();
  }
});

// ==========================================
// SERVER START
// ==========================================

const PORT = process.env.PORT || 3000;

const server = app.listen(PORT, "0.0.0.0", () => {
  console.log(`AlertAgos API running on port ${PORT}`);
});

// ==========================================
// GRACEFUL SHUTDOWN
// ==========================================

let shuttingDown = false;

async function shutdown() {
  if (shuttingDown) return;

  shuttingDown = true;

  console.log("Closing AlertAgos server...");

  server.close(async () => {
    try {
      await driver.close();
      console.log("Neo4j connection closed.");
      process.exit(0);
    } catch (error) {
      console.error("Shutdown error:", error);
      process.exit(1);
    }
  });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
