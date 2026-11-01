require("dotenv").config();

const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const crypto = require("crypto");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const RECEIVE_ADDRESS =
  process.env.TRON_RECEIVE_ADDRESS ||
  "TVFeDBy2GFPNB5JJgNpRF8otsFcRVPb4ak";

const TRON_BASE =
  process.env.TRON_NETWORK === "nile"
    ? "https://nile.trongrid.io"
    : "https://api.trongrid.io";

// Official USDT TRC20 contract
const USDT_CONTRACT_HEX =
  "41a614f803b6fd780986a42c78ec9c7f77e6ded13c";

const TRANSFER_TOPIC =
  "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

const PLANS = {
  basic: {
    name: "Basic",
    price: 5,
    days: 30,
    features: [
      "Landing Page Builder",
      "Basic Click Protection",
      "1 Published Page"
    ]
  },

  prime: {
    name: "Prime & Pro",
    price: 12,
    days: 30,
    features: [
      "Landing Page Builder",
      "Visitor Tracking",
      "Lead Analytics",
      "5 Published Pages"
    ]
  },

  combo: {
    name: "Basic & Prime",
    price: 15,
    days: 30,
    features: [
      "All Basic Features",
      "Visitor Analytics",
      "Suspicious Click Reports",
      "10 Published Pages"
    ]
  }
};

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("JWT_SECRET must be at least 32 characters.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.DB_SSL === "true"
      ? { rejectUnauthorized: false }
      : undefined
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  "/api/",
  rateLimit({
    windowMs: 60000,
    limit: 100,
    standardHeaders: true,
    legacyHeaders: false
  })
);

async function db(sql, params = []) {
  return pool.query(sql, params);
}

// DATABASE TABLES

async function initDb() {
  await db(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT DEFAULT 'customer',
      subscription_plan TEXT,
      subscription_expires_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS pages (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      slug TEXT UNIQUE NOT NULL,
      headline TEXT NOT NULL,
      description TEXT DEFAULT '',
      button_text TEXT DEFAULT 'Contact on WhatsApp',
      whatsapp_number TEXT DEFAULT '',
      image_url TEXT DEFAULT '',
      pixel_id TEXT DEFAULT '',
      published BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMPTZ DEFAULT NOW(),
      updated_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS payments (
      id BIGSERIAL PRIMARY KEY,
      user_id BIGINT REFERENCES users(id) ON DELETE CASCADE,
      plan_key TEXT NOT NULL,
      txid TEXT UNIQUE NOT NULL,
      amount NUMERIC(18,6) NOT NULL,
      status TEXT DEFAULT 'verified',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS events (
      id BIGSERIAL PRIMARY KEY,
      page_id BIGINT REFERENCES pages(id) ON DELETE CASCADE,
      event_type TEXT NOT NULL,
      visitor_hash TEXT NOT NULL,
      suspicious BOOLEAN DEFAULT FALSE,
      user_agent TEXT DEFAULT '',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS events_page_created_idx
    ON events(page_id, created_at);
  `);

  const email = (process.env.ADMIN_EMAIL || "").toLowerCase().trim();
  const password = process.env.ADMIN_PASSWORD || "";

  if (email && password.length >= 12) {
    const existing = await db(
      "SELECT id FROM users WHERE email=$1",
      [email]
    );

    if (!existing.rowCount) {
      const hash = await bcrypt.hash(password, 12);

      await db(
        `INSERT INTO users(name,email,password_hash,role)
         VALUES($1,$2,$3,'admin')`,
        ["Administrator", email, hash]
      );

      console.log("Admin account created:", email);
    }
  }
}

// HELPERS

function clean(value, max = 500) {
  return String(value || "").trim().slice(0, max);
}

function slugify(value) {
  return String(value || "")
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 50) || "my-page";
}

function makeToken(user) {
  return jwt.sign(
    {
      id: user.id,
      email: user.email,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function auth(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({
      error: "Please login again."
    });
  }
}

function adminOnly(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({
      error: "Admin access only."
    });
  }
  next();
}

function activeSubscription(user) {
  return (
    user &&
    user.subscription_expires_at &&
    new Date(user.subscription_expires_at).getTime() > Date.now()
  );
}

function visitorHash(req) {
  const ip = String(
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    ""
  ).split(",")[0].trim();

  return crypto
    .createHash("sha256")
    .update(
      ip +
      "|" +
      (req.headers["user-agent"] || "") +
      "|" +
      JWT_SECRET
    )
    .digest("hex");
}

function suspiciousRequest(req) {
  const ua = String(
    req.headers["user-agent"] || ""
  ).toLowerCase();

  return (
    !ua ||
    /(bot|crawler|spider|headless|curl|wget|python-requests|scrapy)/i.test(ua)
  );
}

// TRON ADDRESS CONVERSION

function base58ToHexAddress(address) {
  const alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

  let n = 0n;

  for (const c of address) {
    const i = alphabet.indexOf(c);

    if (i < 0) {
      throw new Error("Invalid TRON address.");
    }

    n = n * 58n + BigInt(i);
  }

  let hex = n.toString(16).padStart(50, "0");
  let bytes = Buffer.from(hex, "hex");

  let leading = 0;

  for (const c of address) {
    if (c === "1") leading++;
    else break;
  }

  if (leading) {
    bytes = Buffer.concat([
      Buffer.alloc(leading),
      bytes
    ]);
  }

  if (bytes.length !== 25) {
    throw new Error("Invalid TRON address length.");
  }

  const payload = bytes.subarray(0, 21);

  const checksum = crypto
    .createHash("sha256")
    .update(
      crypto.createHash("sha256")
        .update(payload)
        .digest()
    )
    .digest()
    .subarray(0, 4);

  if (!checksum.equals(bytes.subarray(21))) {
    throw new Error("Invalid TRON address checksum.");
  }

  return payload.toString("hex").toLowerCase();
}

// VERIFY USDT PAYMENT

async function verifyTrc20Payment(txid, expectedAmount) {
  if (!/^[a-fA-F0-9]{64}$/.test(txid)) {
    throw new Error("Invalid transaction ID.");
  }

  const headers = {
    "Content-Type": "application/json"
  };

  if (process.env.TRONGRID_API_KEY) {
    headers["TRON-PRO-API-KEY"] =
      process.env.TRONGRID_API_KEY;
  }

  const response = await fetch(
    `${TRON_BASE}/walletsolidity/gettransactioninfobyid`,
    {
      method: "POST",
      headers,
      body: JSON.stringify({ value: txid })
    }
  );

  if (!response.ok) {
    throw new Error("TRON verification service unavailable.");
  }

  const info = await response.json();

  if (
    !info ||
    !info.id ||
    !info.blockNumber ||
    info.result !== "SUCCESS"
  ) {
    throw new Error("Transaction not confirmed or unsuccessful.");
  }

  const receiverHex =
    base58ToHexAddress(RECEIVE_ADDRESS);

  const logs = Array.isArray(info.log)
    ? info.log
    : [];

  for (const log of logs) {
    const contract = String(log.address || "")
      .replace(/^0x/i, "")
      .toLowerCase();

    const topics = log.topics || [];

    if (
      contract !== USDT_CONTRACT_HEX.slice(2) &&
      contract !== USDT_CONTRACT_HEX
    ) {
      continue;
    }

    if (
      String(topics[0] || "").toLowerCase() !==
      TRANSFER_TOPIC
    ) {
      continue;
    }

    const toTopic = String(topics[2] || "")
      .toLowerCase()
      .replace(/^0x/, "");

    const toHex = "41" + toTopic.slice(-40);

    if (toHex !== receiverHex) {
      continue;
    }

    const raw = BigInt("0x" + String(log.data || "0"));
    const amount = Number(raw) / 1e6;

    if (Math.abs(amount - expectedAmount) > 0.000001) {
      continue;
    }

    return {
      amount: amount.toFixed(6),
      blockNumber: info.blockNumber
    };
  }

  throw new Error(
    "Matching confirmed USDT TRC20 payment was not found."
  );
}

// WEBSITE CONFIG

app.get("/api/config", (req, res) => {
  res.json({
    brand: "ADS GROWTH AGENCY PRO",
    receiveAddress: RECEIVE_ADDRESS,
    network: "TRC20",
    plans: PLANS
  });
});

// REGISTER

app.post("/api/auth/register", async (req, res) => {
  try {
    const name = clean(req.body.name, 80);
    const email = clean(req.body.email, 160).toLowerCase();
    const password = String(req.body.password || "");

    if (
      !name ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      password.length < 10
    ) {
      return res.status(400).json({
        error: "Enter name, valid email and password of at least 10 characters."
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await db(
      `INSERT INTO users(name,email,password_hash)
       VALUES($1,$2,$3)
       RETURNING id,name,email,role`,
      [name, email, hash]
    );

    const user = result.rows[0];

    res.json({
      token: makeToken(user),
      user
    });

  } catch (e) {
    res.status(400).json({
      error:
        e.code === "23505"
          ? "Email already registered."
          : "Could not create account."
    });
  }
});

// LOGIN

app.post("/api/auth/login", async (req, res) => {
  const email = clean(req.body.email, 160).toLowerCase();
  const password = String(req.body.password || "");

  const result = await db(
    "SELECT * FROM users WHERE email=$1",
    [email]
  );

  const user = result.rows[0];

  if (
    !user ||
    !(await bcrypt.compare(password, user.password_hash))
  ) {
    return res.status(401).json({
      error: "Email or password incorrect."
    });
  }

  res.json({
    token: makeToken(user),
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role
    }
  });
});

// CURRENT USER

app.get("/api/me", auth, async (req, res) => {
  const r = await db(
    `SELECT id,name,email,role,subscription_plan,
     subscription_expires_at
     FROM users WHERE id=$1`,
    [req.user.id]
  );

  if (!r.rowCount) {
    return res.status(404).json({
      error: "Account not found."
    });
  }

  res.json({
    user: r.rows[0],
    active: activeSubscription(r.rows[0])
  });
});

// PAYMENT VERIFICATION

app.post("/api/payments/verify", auth, async (req, res) => {
  try {
    const planKey = clean(req.body.plan, 20);
    const plan = PLANS[planKey];
    const txid = clean(req.body.txid, 100).toLowerCase();

    if (!plan) {
      return res.status(400).json({
        error: "Select a valid plan."
      });
    }

    const existing = await db(
      "SELECT id FROM payments WHERE txid=$1",
      [txid]
    );

    if (existing.rowCount) {
      return res.status(409).json({
        error: "This transaction was already used."
      });
    }

    const verified = await verifyTrc20Payment(
      txid,
      plan.price
    );

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      await client.query(
        `INSERT INTO payments
         (user_id,plan_key,txid,amount,status)
         VALUES($1,$2,$3,$4,'verified')`,
        [
          req.user.id,
          planKey,
          txid,
          verified.amount
        ]
      );

      await client.query(
        `UPDATE users
         SET subscription_plan=$1,
         subscription_expires_at =
         GREATEST(
           COALESCE(subscription_expires_at,NOW()),
           NOW()
         ) + INTERVAL '30 days'
         WHERE id=$2`,
        [planKey, req.user.id]
      );

      await client.query("COMMIT");

    } catch (e) {
      await client.query("ROLLBACK");
      throw e;
    } finally {
      client.release();
    }

    res.json({
      success: true,
      message: "Payment verified. Subscription active for 30 days.",
      amount: verified.amount,
      blockNumber: verified.blockNumber
    });

  } catch (e) {
    res.status(400).json({
      error: e.message || "Payment verification failed."
    });
  }
});

// GET CUSTOMER PAGES

app.get("/api/pages", auth, async (req, res) => {
  const r = await db(
    `SELECT * FROM pages
     WHERE user_id=$1
     ORDER BY created_at DESC`,
    [req.user.id]
  );

  res.json(r.rows);
});

// CREATE PAGE

app.post("/api/pages", auth, async (req, res) => {
  const title = clean(req.body.title, 100);
  const headline = clean(req.body.headline, 160);
  const description = clean(req.body.description, 1000);

  if (!title || !headline) {
    return res.status(400).json({
      error: "Page title and headline required."
    });
  }

  const slug =
    slugify(title) +
    "-" +
    crypto.randomBytes(2).toString("hex");

  const r = await db(
    `INSERT INTO pages
     (user_id,title,slug,headline,description,
      button_text,whatsapp_number,image_url,pixel_id)
     VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)
     RETURNING *`,
    [
      req.user.id,
      title,
      slug,
      headline,
      description,
      clean(req.body.buttonText, 60) || "Contact on WhatsApp",
      clean(req.body.whatsappNumber, 30),
      clean(req.body.imageUrl, 500),
      clean(req.body.pixelId, 30)
    ]
  );

  res.json(r.rows[0]);
});

// UPDATE PAGE

app.put("/api/pages/:id", auth, async (req, res) => {
  const r = await db(
    `UPDATE pages
     SET title=$1,headline=$2,description=$3,
     button_text=$4,whatsapp_number=$5,
     image_url=$6,pixel_id=$7,updated_at=NOW()
     WHERE id=$8 AND user_id=$9
     RETURNING *`,
    [
      clean(req.body.title, 100),
      clean(req.body.headline, 160),
      clean(req.body.description, 1000),
      clean(req.body.buttonText, 60),
      clean(req.body.whatsappNumber, 30),
      clean(req.body.imageUrl, 500),
      clean(req.body.pixelId, 30),
      req.params.id,
      req.user.id
    ]
  );

  if (!r.rowCount) {
    return res.status(404).json({
      error: "Page not found."
    });
  }

  res.json(r.rows[0]);
});

// PUBLISH PAGE

app.post("/api/pages/:id/publish", auth, async (req, res) => {
  const u = await db(
    "SELECT subscription_plan,subscription_expires_at FROM users WHERE id=$1",
    [req.user.id]
  );

  if (!activeSubscription(u.rows[0])) {
    return res.status(402).json({
      error: "Active subscription required before publishing."
    });
  }

  const plan = PLANS[u.rows[0].subscription_plan];

  const cap =
    u.rows[0].subscription_plan === "basic" ? 1 :
    u.rows[0].subscription_plan === "prime" ? 5 : 10;

  const target = await db(
    "SELECT id,published FROM pages WHERE id=$1 AND user_id=$2",
    [req.params.id, req.user.id]
  );

  if (!target.rowCount) {
    return res.status(404).json({
      error: "Page not found."
    });
  }

  const count = await db(
    `SELECT COUNT(*)::int AS n
     FROM pages
     WHERE user_id=$1 AND published=true`,
    [req.user.id]
  );

  if (count.rows[0].n >= cap && !target.rows[0].published) {
    return res.status(403).json({
      error: `Your plan allows ${cap} published pages.`
    });
  }

  const r = await db(
    `UPDATE pages SET published=true,updated_at=NOW()
     WHERE id=$1 AND user_id=$2 RETURNING slug`,
    [req.params.id, req.user.id]
  );

  res.json({
    success: true,
    url: `/p/${r.rows[0].slug}`
  });
});

// VISITOR TRACKING

app.post("/api/track/:slug", async (req, res) => {
  const p = await db(
    "SELECT id FROM pages WHERE slug=$1 AND published=true",
    [req.params.slug]
  );

  if (!p.rowCount) {
    return res.status(404).end();
  }

  const type = ["visit", "lead", "click"].includes(req.body.type)
    ? req.body.type
    : "visit";

  await db(
    `INSERT INTO events
     (page_id,event_type,visitor_hash,suspicious,user_agent)
     VALUES($1,$2,$3,$4,$5)`,
    [
      p.rows[0].id,
      type,
      visitorHash(req),
      suspiciousRequest(req),
      clean(req.headers["user-agent"], 300)
    ]
  );

  res.json({ ok: true });
});

// ANALYTICS

app.get("/api/analytics", auth, async (req, res) => {
  const r = await db(
    `SELECT
      p.id,
      p.title,
      p.slug,
      COUNT(e.id)::int AS events,
      COUNT(e.id) FILTER
        (WHERE e.event_type='visit')::int AS visits,
      COUNT(e.id) FILTER
        (WHERE e.event_type='lead')::int AS leads,
      COUNT(e.id) FILTER
        (WHERE e.suspicious=true)::int AS suspicious
     FROM pages p
     LEFT JOIN events e ON e.page_id=p.id
     WHERE p.user_id=$1
     GROUP BY p.id
     ORDER BY p.created_at DESC`,
    [req.user.id]
  );

  res.json(r.rows);
});

// ADMIN DASHBOARD DATA

app.get("/api/admin/overview", auth, adminOnly, async (req, res) => {
  const [users, pages, payments, events] = await Promise.all([
    db("SELECT COUNT(*)::int AS n FROM users WHERE role='customer'"),
    db("SELECT COUNT(*)::int AS n FROM pages"),
    db("SELECT COUNT(*)::int AS n, COALESCE(SUM(amount),0)::text AS total FROM payments"),
    db("SELECT COUNT(*)::int AS n, COUNT(*) FILTER(WHERE suspicious=true)::int AS suspicious FROM events")
  ]);

  res.json({
    users: users.rows[0].n,
    pages: pages.rows[0].n,
    payments: payments.rows[0].n,
    usdt: payments.rows[0].total,
    events: events.rows[0].n,
    suspicious: events.rows[0].suspicious
  });
});

// PUBLIC LANDING PAGE

app.get("/p/:slug", async (req, res) => {
  const r = await db(
    "SELECT * FROM pages WHERE slug=$1 AND published=true",
    [req.params.slug]
  );

  if (!r.rowCount) {
    return res.status(404).send("Page not found or not published.");
  }

  const p = r.rows[0];

  const esc = s =>
    String(s || "").replace(/[&<>"']/g, c => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      '"': "&quot;",
      "'": "&#39;"
    }[c]));

  const wa = p.whatsapp_number.replace(/\D/g, "");

  const image =
    p.image_url && /^https?:\/\//i.test(p.image_url)
      ? `<img class="hero-image" src="${esc(p.image_url)}" alt="Product">`
      : "";

  const button = wa
    ? `<a class="cta" href="https://wa.me/${esc(wa)}" onclick="track('lead')">${esc(p.button_text)}</a>`
    : `<a class="cta" href="#contact" onclick="track('click')">${esc(p.button_text)}</a>`;

  const pixel =
    p.pixel_id && /^\d{5,25}$/.test(p.pixel_id)
      ? `<script>
        !function(f,b,e,v,n,t,s){
        if(f.fbq)return;
        n=f.fbq=function(){
        n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)};
        if(!f._fbq)f._fbq=n;
        n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];
        t=b.createElement(e);t.async=!0;
        t.src=v;s=b.getElementsByTagName(e)[0];
        s.parentNode.insertBefore(t,s)
        }(window,document,'script',
        'https://connect.facebook.net/en_US/fbevents.js');
        fbq('init','${esc(p.pixel_id)}');
        fbq('track','PageView');
        </script>`
      : "";

  res.send(`
    <!doctype html>
    <html>
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width,initial-scale=1">
      <title>${esc(p.title)}</title>
      ${pixel}
      <style>
        *{
