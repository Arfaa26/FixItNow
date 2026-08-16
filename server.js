
require("dotenv").config();
const express = require("express");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const multer = require("multer");
const Database = require("better-sqlite3");

const app = express();
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || "0.0.0.0";
const NODE_ENV = process.env.NODE_ENV || "development";
const JWT_SECRET = process.env.JWT_SECRET || (NODE_ENV === "production" ? "" : "fixitnow-development-secret");
if (NODE_ENV === "production" && JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET must be at least 32 characters in production.");
}
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
const GEMINI_MODEL = process.env.GEMINI_MODEL || "gemini-2.5-flash";
let geminiClient = null;

async function getGeminiClient() {
  if (!GEMINI_API_KEY) return null;
  if (!geminiClient) {
    const { GoogleGenAI } = await import("@google/genai");
    geminiClient = new GoogleGenAI({ apiKey: GEMINI_API_KEY });
  }
  return geminiClient;
}

const publicDir = path.join(__dirname, "public");
// Set DATA_DIR to a persistent volume in production (for example /var/data on Render).
const dataDir = process.env.DATA_DIR || path.join(__dirname, "data");
const uploadDir = path.join(dataDir, "uploads");
fs.mkdirSync(uploadDir, { recursive: true });

const db = new Database(path.join(dataDir, "fixitnow.db"));
db.pragma("journal_mode = WAL");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS diagnoses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  device TEXT NOT NULL,
  symptom TEXT NOT NULL,
  image_url TEXT,
  title TEXT NOT NULL,
  difficulty TEXT,
  cost TEXT,
  time TEXT,
  recommendation TEXT,
  note TEXT,
  safety TEXT,
  source TEXT NOT NULL DEFAULT 'rules',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

const storage = multer.diskStorage({
  destination: (_, __, cb) => cb(null, uploadDir),
  filename: (_, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase().replace(/[^a-z0-9.]/g, "");
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${ext || ".jpg"}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter: (_, file, cb) => {
    const ok = /^image\/(jpeg|png|webp|gif)$/.test(file.mimetype);
    cb(ok ? null : new Error("Only JPG, PNG, WEBP, or GIF images are allowed."), ok);
  }
});

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("X-Frame-Options", "SAMEORIGIN");
  next();
});
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
// Serve the frontend explicitly. This route must stay before any API/404 handlers.
app.use(express.static(publicDir));
app.get("/", (req, res) => {
  const indexFile = path.join(publicDir, "index.html");
  if (!fs.existsSync(indexFile)) {
    return res.status(500).send("FixItNow frontend is missing: public/index.html");
  }
  res.sendFile(indexFile);
});
app.use("/uploads", express.static(uploadDir, { fallthrough: false, maxAge: "7d" }));

function signUser(user) {
  return jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: "7d" });
}
function auth(req, res, next) {
  const token = req.cookies.fixitnow_token;
  if (!token) return res.status(401).json({ error: "Please sign in first." });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Your session expired. Please sign in again." });
  }
}
function normalize(s) { return String(s || "").toLowerCase(); }

const rules = [
  {device:"outlet", kw:["spark","shock","burn","smoke","hot to touch"], title:"Possible wiring fault", difficulty:"Do not DIY", cost:"—", time:"—", recommendation:"Call a technician", safety:"STOP. This can involve live electrical wiring. Do not open the outlet or continue testing it.", note:"Switch off the affected circuit if you can do so safely without touching damaged wiring, and contact a licensed electrician."},
  {device:"washer", kw:["leak","water","seal","drip"], title:"Worn door seal or hose", difficulty:"Moderate", cost:"₹1,200 – ₹5,000", time:"30–60 min", recommendation:"Repair", safety:"Unplug before inspecting external hoses or the door gasket.", note:"Check the door gasket for visible tears and the drain hose connection. Replace damaged external parts rather than opening the electrical cabinet."},
  {device:"washer", kw:["noise","grinding","shak","loud","bang"], title:"Possible drum bearing or balance issue", difficulty:"Hard", cost:"₹4,000 – ₹15,000", time:"1–3 hrs", recommendation:"Call a technician", safety:"Keep hands away from moving parts and unplug before any inspection.", note:"Grinding during spin can indicate bearings or suspension components. A technician quote is sensible before buying parts."},
  {device:"laptop", kw:["crack","flicker","screen","dim","line"], title:"Display panel or cable fault", difficulty:"Moderate", cost:"₹3,000 – ₹18,000", time:"1–3 hrs", recommendation:"Repair", safety:"Power down and unplug. Do not work on a swollen or damaged battery.", note:"A visible crack usually means panel replacement; flicker can also come from the display cable or graphics hardware."},
  {device:"laptop", kw:["charg","battery","power","will not turn on","won't turn on"], title:"Charging path or battery issue", difficulty:"Easy–Moderate", cost:"₹1,500 – ₹8,000", time:"20–90 min", recommendation:"Repair", safety:"If the battery is swollen, hot, smoking, or leaking, stop using the laptop and seek professional service.", note:"Try a known-good charger and wall outlet first. If the charging port is loose, professional repair may be safer than opening the device."},
  {device:"lamp", kw:["flicker","will not turn on","won't turn on","dim","bulb"], title:"Loose bulb or worn switch", difficulty:"Easy", cost:"₹150 – ₹1,500", time:"10–20 min", recommendation:"Repair", safety:"Unplug the lamp before changing a bulb or inspecting an external switch.", note:"Reseat the bulb and try a compatible replacement. Do not open mains wiring if you are not qualified."},
  {device:"blender", kw:["smell","burn","motor","smoke","overheat"], title:"Motor overheating", difficulty:"Do not DIY", cost:"—", time:"—", recommendation:"Call a technician", safety:"STOP. A burning smell or smoke is a safety warning. Unplug it and do not run it again.", note:"Let the appliance cool and have the motor, wiring, and control components checked."},
  {device:"blender", kw:["leak","loose","blade","will not spin","won't spin"], title:"Worn gasket or blade assembly", difficulty:"Easy", cost:"₹800 – ₹2,500", time:"15–30 min", recommendation:"Repair", safety:"Unplug before handling the blade assembly.", note:"A seal, coupling, or blade assembly can cause these symptoms. Replace damaged parts rather than forcing the mechanism."},
  {device:"fridge", kw:["not cold","warm","ice","frost","noise"], title:"Cooling or airflow issue", difficulty:"Moderate", cost:"₹500 – ₹8,000+", time:"30–120 min", recommendation:"Needs more detail", safety:"Do not puncture refrigerant lines or dismantle the sealed cooling system.", note:"Check temperature settings, door sealing, and visible airflow obstruction. Refrigerant or compressor work requires a qualified technician."},
  {device:"dishwasher", kw:["leak","water","drain","smell","not cleaning"], title:"Filter, drain, or seal issue", difficulty:"Easy–Moderate", cost:"₹500 – ₹4,000", time:"20–60 min", recommendation:"Repair", safety:"Switch off and unplug before reaching into the unit.", note:"Clean the accessible filter and check the door seal and drain area for obvious blockage."},
  {device:"tv", kw:["screen","flicker","no picture","sound","remote"], title:"Display, input, or control issue", difficulty:"Easy–Moderate", cost:"₹300 – ₹20,000+", time:"10–120 min", recommendation:"Needs more detail", safety:"Do not open a TV power supply or CRT-style equipment.", note:"Check input source, cables, remote batteries, and power-cycle the TV. Internal power-board work should be professional."}
];

function ruleDiagnosis(device, symptom) {
  const s = normalize(symptom);
  let match = rules.find(r => r.device === device && r.kw.some(k => s.includes(k)));
  if (!match) {
    match = {
      title: "A few possibilities to narrow down",
      difficulty: "Depends",
      cost: "₹500 – ₹15,000",
      time: "Varies",
      recommendation: "Needs more detail",
      safety: "Do not open mains-powered equipment, gas appliances, sealed batteries, or refrigerant systems.",
      note: "Add a sound, smell, warning light/error code, when the problem happens, and what changed immediately before it started."
    };
  }
  return {...match, source:"rules"};
}

async function aiDiagnosis({device, symptom, imageFile}) {
  const ai = await getGeminiClient();
  if (!ai) return null;

  const system = `You are FixItNow, a safety-first household repair assistant.
Analyze the user's appliance/device and symptom, optionally using the attached photo.
Return ONLY valid JSON with exactly these fields:
title, difficulty, cost, time, recommendation, safety, note.
Rules:
- Be conservative. A photo cannot prove an internal fault.
- Never tell a user to open live mains wiring, gas systems, sealed refrigerant systems, swollen/damaged batteries, high-voltage equipment, or other hazardous internals.
- If a dangerous condition is suspected, recommendation must be "Call a technician".
- Cost must be a rough India estimate in INR and explicitly approximate when possible.
- If evidence is insufficient, say so and ask for useful non-dangerous observations in note.
- Keep safety prominent and practical.
- Do not invent exact part numbers or certainty.`;

  const parts = [
    { text: `${system}\n\nDevice: ${device}\nSymptom: ${symptom || "(no text symptom; inspect the image carefully)"}\nProvide the safest useful diagnosis.` }
  ];

  if (imageFile) {
    const imageBytes = fs.readFileSync(imageFile.path).toString("base64");
    parts.push({
      inlineData: {
        mimeType: imageFile.mimetype,
        data: imageBytes
      }
    });
  }

  const response = await ai.models.generateContent({
    model: GEMINI_MODEL,
    contents: [{ role: "user", parts }],
    config: {
      responseMimeType: "application/json"
    }
  });

  const raw = response.text || "";
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error("Gemini returned an invalid diagnosis format.");
  }

  const required = ["title","difficulty","cost","time","recommendation","safety","note"];
  for (const key of required) {
    if (typeof parsed[key] !== "string") parsed[key] = String(parsed[key] ?? "");
  }
  return {...parsed, source:"gemini"};
}

app.post("/api/auth/register", async (req,res) => {
  try {
    const name = String(req.body.name || "").trim();
    const email = String(req.body.email || "").trim().toLowerCase();
    const password = String(req.body.password || "");
    if (name.length < 2) return res.status(400).json({error:"Enter your name."});
    if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({error:"Enter a valid email."});
    if (password.length < 6) return res.status(400).json({error:"Password must be at least 6 characters."});
    const hash = await bcrypt.hash(password, 12);
    const info = db.prepare("INSERT INTO users(name,email,password_hash) VALUES(?,?,?)").run(name,email,hash);
    const user = db.prepare("SELECT id,name,email,created_at FROM users WHERE id=?").get(info.lastInsertRowid);
    res.cookie("fixitnow_token", signUser(user), {httpOnly:true, sameSite:"lax", secure:NODE_ENV==="production", maxAge:7*24*60*60*1000});
    res.json({user});
  } catch(e) {
    if (String(e.message).includes("UNIQUE")) return res.status(409).json({error:"An account with that email already exists."});
    res.status(500).json({error:"Could not create the account."});
  }
});

app.post("/api/auth/login", async (req,res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!user || !(await bcrypt.compare(password,user.password_hash))) return res.status(401).json({error:"Incorrect email or password."});
  const safe = {id:user.id,name:user.name,email:user.email,created_at:user.created_at};
  res.cookie("fixitnow_token", signUser(safe), {httpOnly:true, sameSite:"lax", secure:NODE_ENV==="production", maxAge:7*24*60*60*1000});
  res.json({user:safe});
});

app.post("/api/auth/logout", (_,res) => {
  res.clearCookie("fixitnow_token");
  res.json({ok:true});
});

app.get("/health", (_,res) => res.json({
  ok:true,
  service:"fixitnow",
  timestamp:new Date().toISOString(),
  frontend:fs.existsSync(path.join(publicDir, "index.html"))
}));
app.get("/__fixitnow-version", (_,res) => res.json({
  version:"1.0.1",
  frontend:fs.existsSync(path.join(publicDir, "index.html")),
  publicDir
}));

app.get("/api/me", auth, (req,res) => {
  const user = db.prepare("SELECT id,name,email,created_at FROM users WHERE id=?").get(req.user.id);
  res.json({user});
});

app.get("/api/history", auth, (req,res) => {
  const rows = db.prepare("SELECT * FROM diagnoses WHERE user_id=? ORDER BY id DESC LIMIT 100").all(req.user.id);
  res.json({history:rows});
});

app.post("/api/diagnose", auth, upload.single("photo"), async (req,res) => {
  try {
    const device = String(req.body.device || "").trim();
    const symptom = String(req.body.symptom || "").trim();
    if (!device) return res.status(400).json({error:"Choose a device."});
    if (symptom.length < 3 && !req.file) return res.status(400).json({error:"Describe the symptom or add a photo."});

    let result = null;
    if (GEMINI_API_KEY) {
      try { result = await aiDiagnosis({device, symptom, imageFile:req.file}); }
      catch (e) { console.error("AI diagnosis failed:", e.message); }
    }
    if (!result) result = ruleDiagnosis(device, symptom);

    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const insert = db.prepare(`
      INSERT INTO diagnoses(user_id,device,symptom,image_url,title,difficulty,cost,time,recommendation,note,safety,source)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
    `);
    const info = insert.run(req.user.id, device, symptom, imageUrl, result.title, result.difficulty, result.cost, result.time, result.recommendation, result.note, result.safety, result.source);
    const saved = db.prepare("SELECT * FROM diagnoses WHERE id=?").get(info.lastInsertRowid);
    res.json({diagnosis:saved, aiEnabled:Boolean(GEMINI_API_KEY)});
  } catch(e) {
    console.error(e);
    res.status(500).json({error:e.message || "Diagnosis failed."});
  }
});

app.delete("/api/history/:id", auth, (req,res) => {
  const row = db.prepare("SELECT * FROM diagnoses WHERE id=? AND user_id=?").get(req.params.id, req.user.id);
  if (!row) return res.status(404).json({error:"Diagnosis not found."});
  db.prepare("DELETE FROM diagnoses WHERE id=? AND user_id=?").run(req.params.id, req.user.id);
  if (row.image_url) {
    const file = path.join(uploadDir, path.basename(row.image_url));
    if (file.startsWith(uploadDir) && fs.existsSync(file)) fs.unlinkSync(file);
  }
  res.json({ok:true});
});

app.post("/api/contact", (req,res) => {
  const email = String(req.body.email || "").trim();
  const message = String(req.body.message || "").trim();
  if (!/^\S+@\S+\.\S+$/.test(email) || message.length < 5) return res.status(400).json({error:"Enter a valid email and message."});
  console.log(`[CONTACT] ${email}: ${message}`);
  res.json({ok:true,message:"Thanks — your message has been received."});
});

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError || err.message?.includes("Only JPG")) return res.status(400).json({error:err.message});
  next(err);
});

const server = app.listen(PORT, HOST, () => {
  console.log(`FixItNow running on ${HOST}:${PORT}`);
  console.log(`Database: ${path.join(dataDir,"fixitnow.db")}`);
  console.log(`Gemini diagnosis: ${GEMINI_API_KEY ? `enabled (${GEMINI_MODEL})` : "fallback rules enabled"}`);
});


function shutdown(signal) {
  console.log(`${signal} received; shutting down...`);
  server.close(() => { db.close(); process.exit(0); });
  setTimeout(() => process.exit(1), 10000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
