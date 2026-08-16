
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
  evidence TEXT,
  causes TEXT,
  steps TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
);
`);

// Upgrade databases created by older FixItNow versions without destroying history.
for (const [name, type] of [["evidence","TEXT"],["causes","TEXT"],["steps","TEXT"]]) {
  try { db.exec(`ALTER TABLE diagnoses ADD COLUMN ${name} ${type}`); } catch (_) {}
}

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
  {device:"outlet", kw:["spark","shock","burn","smoke","hot to touch","sparking"],
   title:"Possible electrical fault", difficulty:"Do not DIY", cost:"₹500 – ₹2,500+", time:"30–90 min",
   recommendation:"Call a technician", safety:"STOP. Do not touch exposed wiring, a sparking outlet, smoke, or a hot socket. Switch off the affected circuit only if you can do so safely.",
   evidence:["Sparking, heat, burning smell, smoke, or shocks point to an electrical fault that should be professionally inspected."],
   causes:["Loose connection","Overloaded or damaged socket","Worn internal wiring"],
   steps:["Stop using the outlet.","Keep flammable items away.","If safe, switch off the relevant breaker.","Arrange a licensed electrician inspection."],
   note:"Do not remove the faceplate or test live wiring yourself."},

  {device:"washer", kw:["leak","water","seal","drip"],
   title:"Likely leak from the door seal or hose connection", difficulty:"Easy–Moderate", cost:"₹500 – ₹5,000", time:"20–60 min",
   recommendation:"Repair", safety:"Unplug the washer before inspecting external hoses or the door gasket. Do not work around exposed electrical connections.",
   evidence:["A water leak is commonly caused by a damaged door gasket, loose hose connection, or blocked/draining path."],
   causes:["Door gasket tear or poor seal","Loose/damaged inlet or drain hose","Drain/filter blockage"],
   steps:["Unplug the washer.","Check the door gasket for cuts, trapped objects, or deformation.","Check visible hose connections for looseness or cracks.","Clean the accessible drain filter if the manual allows it.","Replace a visibly damaged gasket or hose."],
   note:"If water is coming from underneath the cabinet or near electrical components, stop and get it inspected."},

  {device:"washer", kw:["noise","grinding","shak","loud","bang","vibration"],
   title:"Possible drum bearing or suspension problem", difficulty:"Moderate–Hard", cost:"₹4,000 – ₹15,000", time:"1–3 hrs",
   recommendation:"Call a technician", safety:"Keep hands away from moving parts. Unplug before any physical inspection.",
   evidence:["Grinding or heavy vibration during spin is more consistent with a mechanical drum, bearing, suspension, or load-balance problem than a software issue."],
   causes:["Worn drum bearing","Worn suspension/shock absorber","Unbalanced load or foreign object"],
   steps:["Run an empty spin cycle and note whether the noise remains.","Check that the machine is level and stable.","With the machine unplugged, gently check whether the drum has unusual play.","If grinding persists, stop using it and request a technician inspection."],
   note:"A technician should confirm the bearing/suspension before you buy replacement parts."},

  {device:"laptop", kw:["crack","flicker","screen","dim","line","lines","display"],
   title:"Likely display panel or display-cable issue", difficulty:"Moderate", cost:"₹3,000 – ₹18,000", time:"1–3 hrs",
   recommendation:"Repair", safety:"Power down and unplug. Never open or handle a swollen, hot, leaking, or damaged battery.",
   evidence:["Visible cracks strongly suggest panel damage; intermittent flicker or lines can also come from the display cable or graphics hardware."],
   causes:["Cracked LCD/OLED panel","Loose or damaged display cable","Graphics/display hardware fault"],
   steps:["Connect an external monitor if available.","Check whether the external display is normal.","If only the laptop panel is affected, have the panel/cable inspected.","Back up important data before repair if the laptop is still usable."],
   note:"If the battery is swollen or the chassis is lifting, stop using the laptop and seek professional service."},

  {device:"laptop", kw:["charg","battery","power","will not turn on","won't turn on","not charging"],
   title:"Charging path, adapter, or battery issue", difficulty:"Easy–Moderate", cost:"₹1,500 – ₹8,000", time:"20–90 min",
   recommendation:"Repair", safety:"If the battery is swollen, hot, smoking, or leaking, stop using the laptop immediately.",
   evidence:["Failure to charge or power on can come from the charger, wall outlet, charging port, battery, or power circuitry."],
   causes:["Faulty charger/adapter","Damaged charging port","Worn battery","Internal power fault"],
   steps:["Try a known-good wall outlet.","Check the charger and cable for visible damage.","Try a compatible known-good charger if available.","If the port is loose or the laptop remains dead, arrange a service inspection."],
   note:"Do not keep using a damaged charger or a visibly swollen battery."},

  {device:"lamp", kw:["flicker","will not turn on","won't turn on","dim","bulb"],
   title:"Likely bulb, socket, or switch problem", difficulty:"Easy", cost:"₹150 – ₹1,500", time:"10–20 min",
   recommendation:"Repair", safety:"Unplug the lamp before changing a bulb or checking an external switch. Do not open mains wiring.",
   evidence:["Flickering or no light is commonly caused by the bulb, socket contact, switch, or supply connection."],
   causes:["Failed/incompatible bulb","Loose bulb contact","Worn switch or socket"],
   steps:["Unplug the lamp.","Fit a compatible replacement bulb.","Check the plug and cable for visible damage.","If it still flickers or smells burnt, stop using it and get it inspected."],
   note:"A burning smell, melted plastic, or sparking means stop using the lamp."},

  {device:"blender", kw:["smell","burn","motor","smoke","overheat","hot"],
   title:"Motor overheating or electrical fault", difficulty:"Do not DIY", cost:"₹500 – ₹3,500+", time:"30–90 min",
   recommendation:"Call a technician", safety:"STOP. Burning smell, smoke, or excessive heat can indicate an electrical or motor fault. Unplug it and do not run it again.",
   evidence:["Burning smell, smoke, or abnormal heat is a safety warning rather than a normal operating symptom."],
   causes:["Overloaded motor","Blocked blade assembly","Worn motor/coupling","Electrical fault"],
   steps:["Unplug the blender.","Allow it to cool completely.","Check only for obvious food blockage around the removable blade jar.","If the smell or heat returns, stop using it and arrange service."],
   note:"Do not open the motor housing."},

  {device:"blender", kw:["leak","loose","blade","will not spin","won't spin"],
   title:"Possible blade assembly, coupling, or gasket issue", difficulty:"Easy–Moderate", cost:"₹500 – ₹2,500", time:"15–30 min",
   recommendation:"Repair", safety:"Unplug before handling the blade assembly. Never reach into the jar while the motor is connected to power.",
   evidence:["Leaks around the jar or a blade that does not rotate can come from a worn gasket, coupling, or jammed blade assembly."],
   causes:["Worn jar gasket","Jammed blade","Worn motor coupling"],
   steps:["Unplug the blender.","Remove the jar according to the manufacturer's instructions.","Check the gasket for damage and clean obvious food residue.","Do not force a jammed blade; replace damaged parts or seek service."],
   note:"If there is a burning smell or motor overheating, use the electrical-fault guidance instead."},

  {device:"fridge", kw:["not cold","warm","ice","frost","noise","cooling"],
   title:"Likely airflow, temperature, or defrost issue", difficulty:"Easy–Moderate", cost:"₹500 – ₹8,000+", time:"20–120 min",
   recommendation:"Needs more detail", safety:"Do not puncture refrigerant lines or dismantle the sealed cooling system.",
   evidence:["Poor cooling can be caused by temperature settings, blocked airflow, a door seal, excessive frost, or a cooling-system fault."],
   causes:["Blocked internal airflow","Door seal problem","Excessive frost/defrost issue","Compressor or refrigerant fault"],
   steps:["Confirm the temperature setting.","Make sure internal vents are not blocked by food.","Check the door gasket for gaps or damage.","If there is heavy frost, unusual compressor noise, or persistent warming, arrange service."],
   note:"Refrigerant and compressor work must be handled by a qualified technician."},

  {device:"dishwasher", kw:["leak","water","drain","smell","not cleaning"],
   title:"Likely filter, drain, spray-arm, or door-seal issue", difficulty:"Easy–Moderate", cost:"₹500 – ₹4,000", time:"20–60 min",
   recommendation:"Repair", safety:"Switch off and unplug before reaching into the unit.",
   evidence:["Poor cleaning, standing water, smell, or leaks often start with a blocked filter, drain path, spray arm, or door seal."],
   causes:["Clogged filter","Blocked drain path","Blocked spray arm","Damaged door seal"],
   steps:["Switch off and unplug the dishwasher.","Clean the accessible filter.","Check spray-arm holes for food debris.","Check the door seal for obvious damage.","If it still leaks or fails to drain, arrange service."],
   note:"Do not dismantle internal electrical components."},

  {device:"tv", kw:["screen","flicker","no picture","sound","remote","black screen"],
   title:"Likely input, cable, display, or power issue", difficulty:"Easy–Moderate", cost:"₹300 – ₹20,000+", time:"10–120 min",
   recommendation:"Needs more detail", safety:"Do not open a TV power supply. Internal capacitors can retain dangerous voltage even after unplugging.",
   evidence:["A black/flickering screen can come from the input source, cable, backlight, panel, or power board."],
   causes:["Wrong input/source","Loose HDMI or power cable","Backlight/panel fault","Power-board issue"],
   steps:["Power-cycle the TV.","Confirm the correct input/source.","Reconnect the HDMI and power cables.","Try another input or source device.","If the TV remains black but audio works, request a display/backlight diagnosis."],
   note:"Avoid opening the TV cabinet yourself."}
];

function ruleDiagnosis(device, symptom) {
  const s = normalize(symptom);
  let match = rules.find(r => r.device === device && r.kw.some(k => s.includes(k)));
  if (!match) {
    match = {
      title: "More information is needed to narrow this down",
      difficulty: "Depends on the cause", cost: "Varies", time: "Varies",
      recommendation: "Needs more detail",
      safety: "Stay with external, low-risk checks. Do not open mains-powered equipment, gas appliances, sealed batteries, or refrigerant systems.",
      evidence:["The current symptom does not provide enough evidence to name one fault confidently."],
      causes:["Several faults can create similar symptoms."],
      steps:["Tell us exactly when the problem happens.","Add any sound, smell, leak, warning light, error code, or visible damage.","Say what changed immediately before the issue started.","If safe, describe whether the problem happens every time or only during a specific cycle."],
      note:"A clearer symptom description or a focused photo will produce a more useful diagnosis."
    };
  }
  return {...match, source:"rules"};
}

async function aiDiagnosis({device, symptom, imageFile}) {
  const ai = await getGeminiClient();
  if (!ai) return null;

  const system = `You are FixItNow, a practical and safety-first household repair diagnostician.
Your job is NOT to give a vague chatbot answer. Turn the user's symptom (and photo when provided) into a useful troubleshooting plan.

Return ONLY valid JSON with exactly these string fields:
title, evidence, causes, steps, difficulty, cost, time, recommendation, safety, note.

Field rules:
- title: the most likely problem in plain language, e.g. "Likely drain blockage or pump issue".
- evidence: 1-3 concise observations that connect the user's symptom/photo to the diagnosis. Separate multiple items with " | ".
- causes: 2-4 plausible causes, ordered most likely first. Separate with " | ".
- steps: 4-6 numbered, practical, SAFE checks or fixes the user can perform. Separate steps with " | ".
- difficulty: "Easy", "Easy–Moderate", "Moderate", "Hard", or "Do not DIY".
- cost: approximate India repair cost in INR. Use a range and say "approx." when uncertain. If no safe estimate is possible, say "Depends on inspection".
- time: realistic approximate time, not a made-up exact number.
- recommendation: exactly one of "Repair", "Call a technician", "Stop using it", or "Needs more detail".
- safety: a short, prominent safety instruction specific to this device/problem.
- note: explain what would confirm/refute the diagnosis and when professional service is needed.

Reasoning rules:
1. Never claim a photo proves an internal component failure. Use "likely", "possible", or "consistent with" when appropriate.
2. Prefer the simplest plausible cause before expensive internal failures.
3. Give actionable steps, not generic advice.
4. For electrical shock/sparks/smoke/burning smell, gas, refrigerant, high voltage, damaged/swollen batteries, or moving machinery hazards, stop unsafe DIY and recommend professional service.
5. Never instruct the user to open live mains wiring, gas systems, sealed refrigerant systems, power supplies, CRTs, or swollen batteries.
6. If the evidence is insufficient, do NOT invent a diagnosis. Use "Needs more detail" and ask for specific safe observations.
7. Use Indian repair-cost context, but keep estimates approximate.
8. The answer should be understandable to a normal non-technical user.`;

  const parts = [{ text: `${system}

Device: ${device}
User symptom: ${symptom || "(No written symptom; inspect the image, but do not overclaim what it proves.)"}

Return the JSON now.` }];

  if (imageFile) {
    const imageBytes = fs.readFileSync(imageFile.path).toString("base64");
    parts.push({ inlineData: { mimeType: imageFile.mimetype, data: imageBytes } });
  }

  const response = await ai.models.generateContent({
    model: GEMINI_MODEL,
    contents: [{ role: "user", parts }],
    config: { responseMimeType: "application/json", temperature: 0.2 }
  });

  const raw = response.text || "";
  let parsed;
  try { parsed = JSON.parse(raw); }
  catch { throw new Error("Gemini returned an invalid diagnosis format."); }

  const required = ["title","evidence","causes","steps","difficulty","cost","time","recommendation","safety","note"];
  for (const key of required) {
    if (typeof parsed[key] !== "string") parsed[key] = String(parsed[key] ?? "");
  }

  const allowed = new Set(["Repair","Call a technician","Stop using it","Needs more detail"]);
  if (!allowed.has(parsed.recommendation)) parsed.recommendation = "Needs more detail";

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
      INSERT INTO diagnoses(user_id,device,symptom,image_url,title,difficulty,cost,time,recommendation,note,safety,source,evidence,causes,steps)
      VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    `);
    const info = insert.run(
      req.user.id, device, symptom, imageUrl, result.title, result.difficulty, result.cost, result.time,
      result.recommendation, result.note, result.safety, result.source,
      result.evidence || "", result.causes || "", result.steps || ""
    );
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
