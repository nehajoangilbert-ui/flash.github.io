/* FLASH - password + OTP + signed challenge + OTP -> session
   Runs with plain Node 18+ (no npm install needed). Only email-over-SMTP needs `npm install nodemailer`. */
const http = require('http'), https = require('https'), fs = require('fs'), path = require('path'), crypto = require('crypto');

/* ---------- .env loader (no dotenv needed) ---------- */
try {
  fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split(/\r?\n/).forEach(l => {
    const m = l.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^["']|["']$/g, '');
  });
} catch (e) { /* no .env = dev mode */ }

const PORT = process.env.PORT || 3000;
const OTP_MS = 180000, CHAL_MS = 120000, SESS_MS = 300000, LOCK_MS = 300000, MAX_FAIL = 5;

/* ---------- storage ---------- */
const DB = path.join(__dirname, 'users.json');
const users = fs.existsSync(DB) ? JSON.parse(fs.readFileSync(DB, 'utf8')) : {};
const saveUsers = () => fs.writeFileSync(DB, JSON.stringify(users));
const pendingReg = new Map(), flows = new Map(), sessions = new Map(), fails = new Map(), hits = new Map();

/* ---------- real delivery (console if not configured) ---------- */
const pub = msg => Object.assign(new Error(msg), { publicMsg: msg });
function sendSms(to, body) {
  const sid = process.env.TWILIO_SID, tok = process.env.TWILIO_TOKEN;
  if (!sid || !tok) { console.log('[DEV SMS]', to, body); return Promise.resolve(); }
  return new Promise((resolve, reject) => {
    const data = new URLSearchParams({ To: to, From: process.env.TWILIO_FROM, Body: body }).toString();
    const r = https.request({
      hostname: 'api.twilio.com', path: `/2010-04-01/Accounts/${sid}/Messages.json`, method: 'POST', auth: `${sid}:${tok}`,
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(data) }
    }, resp => {
      let b = ''; resp.on('data', c => b += c);
      resp.on('end', () => { if (resp.statusCode < 300) return resolve(); console.error('Twilio error', resp.statusCode, b); reject(pub('Could not send the SMS. Check the Twilio settings and phone number.')); });
    });
    r.on('error', e => { console.error(e); reject(pub('Could not reach the SMS provider.')); });
    r.end(data);
  });
}
let mailer = null;
async function sendMail(to, subject, text) {
  if (!process.env.SMTP_HOST) { console.log('[DEV MAIL]', to, subject, '\n' + text); return; }
  try {
    if (!mailer) mailer = require('nodemailer').createTransport({
      host: process.env.SMTP_HOST, port: +process.env.SMTP_PORT || 587, secure: process.env.SMTP_SECURE === 'true',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } });
    await mailer.sendMail({ from: process.env.MAIL_FROM || process.env.SMTP_USER, to, subject, text });
  } catch (e) { console.error('Mail error', e.message); throw pub('Could not send the email. Check SMTP settings (and run: npm install nodemailer).'); }
}

/* ---------- helpers ---------- */
const sha = s => crypto.createHash('sha256').update(s).digest();
const eq = (a, b) => a.length === b.length && crypto.timingSafeEqual(a, b);
const id = () => crypto.randomBytes(24).toString('base64url');
const scrypt = (pw, salt) => new Promise((res, rej) => crypto.scrypt(pw, salt, 32, { N: 16384, r: 8, p: 1 }, (e, k) => e ? rej(e) : res(k)));
function mkOtp(salt) {
  const code = String(crypto.randomInt(0, 1e8)).padStart(8, '0');
  return { code, otp: { hash: sha(code + salt), exp: Date.now() + OTP_MS, tries: 0 } };
}
function checkOtp(o, salt, code) {
  if (!o || Date.now() > o.exp || o.tries >= 3) return 'expired';
  o.tries++;
  return eq(sha(String(code || '').trim() + salt), o.hash) ? 'ok' : 'wrong';
}
const R = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(obj)); };

/* ---------- lockout: more than 5 wrong attempts locks the account for 5 minutes ---------- */
function lockLeft(email) {
  const f = fails.get(email);
  return f && f.lockUntil > Date.now() ? Math.ceil((f.lockUntil - Date.now()) / 1000) : 0;
}
function bump(email) {
  const f = fails.get(email) || { n: 0, lockUntil: 0 };
  if (f.lockUntil && f.lockUntil <= Date.now()) { f.n = 0; f.lockUntil = 0; }
  f.n++;
  if (f.n > MAX_FAIL) {
    f.lockUntil = Date.now() + LOCK_MS;
    for (const [k, v] of flows) if (v.email === email) flows.delete(k);
    for (const [k, v] of sessions) if (v.email === email) sessions.delete(k);
  }
  fails.set(email, f);
  return { locked: f.lockUntil > Date.now(), left: Math.max(0, MAX_FAIL + 1 - f.n) };
}
const lockedReply = (res, w) => R(res, 423, { error: 'Locked', locked: true, lockSeconds: w });
function bad(res, email, msg) {
  const r = bump(email);
  return r.locked ? lockedReply(res, lockLeft(email)) : R(res, 401, { error: msg, left: r.left });
}
function flow(res, b, stage) {
  const f = flows.get(b.flowId);
  if (!f || f.stage !== stage) { R(res, 400, { error: 'Step expired. Please login again.' }); return null; }
  const w = lockLeft(f.email); if (w) { lockedReply(res, w); return null; }
  return f;
}
const EMAIL = /^[^@\s]+@[^@\s]+\.[^@\s]+$/, PHONE = /^\+[1-9]\d{7,14}$/;
const clean = v => String(v || '').trim().toLowerCase();
const phoneOf = v => String(v || '').replace(/[\s-]/g, '');

/* ---------- API ---------- */
const API = {
  /* 1. register: email + phone + password -> SMS OTP */
  'POST /api/register': async (req, res, b) => {
    const email = clean(b.email), phone = phoneOf(b.phone), pw = String(b.password || '');
    if (!EMAIL.test(email)) return R(res, 400, { error: 'Enter a valid email.' });
    if (!PHONE.test(phone)) return R(res, 400, { error: 'Phone must be international, e.g. +919876543210.' });
    if (pw.length < 8) return R(res, 400, { error: 'Password must be at least 8 characters.' });
    if (users[email]) return R(res, 409, { error: 'Account already exists. Please login.' });
    const salt = crypto.randomBytes(16), regId = id(), { code, otp } = mkOtp(regId);
    await sendSms(phone, `FLASH registration code: ${code}. Valid for 3 minutes. Do not share it.`);
    pendingReg.set(regId, { t: Date.now(), email, phone, salt: salt.toString('base64'), hash: (await scrypt(pw, salt)).toString('base64'), otp, verified: false });
    R(res, 200, { regId, expiresIn: OTP_MS });
  },
  /* 2. verify phone -> make key pair, EMAIL public + private key, store only the public key */
  'POST /api/register/verify': async (req, res, b) => {
    const p = pendingReg.get(b.regId);
    if (!p) return R(res, 400, { error: 'Registration expired. Start again.' });
    const w = lockLeft(p.email); if (w) return lockedReply(res, w);
    if (!p.verified) {
      const r = checkOtp(p.otp, b.regId, b.otp);
      if (r === 'expired') { pendingReg.delete(b.regId); return R(res, 400, { error: 'OTP expired or used up. Start again.' }); }
      if (r === 'wrong') return bad(res, p.email, 'Wrong OTP.');
      p.verified = true;
    }
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const pubPem = publicKey.export({ type: 'spki', format: 'pem' }), prvPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
    await sendMail(p.email, 'Your FLASH passkeys',
      `Welcome to FLASH.\n\nPUBLIC KEY:\n${pubPem}\nPRIVATE KEY (keep secret - FLASH does not store it):\n${prvPem}\n`);
    users[p.email] = { phone: p.phone, salt: p.salt, hash: p.hash, pub: pubPem }; saveUsers();
    pendingReg.delete(b.regId); fails.delete(p.email);
    R(res, 200, { ok: true });
  },
  /* 3. login: email + phone + password -> SMS OTP */
  'POST /api/login': async (req, res, b) => {
    const email = clean(b.email), phone = phoneOf(b.phone), pw = String(b.password || '');
    const w = lockLeft(email); if (w) return lockedReply(res, w);
    const u = users[email], salt = u ? Buffer.from(u.salt, 'base64') : crypto.randomBytes(16);
    const h = await scrypt(pw, salt);
    if (!(u && eq(h, Buffer.from(u.hash, 'base64')) && u.phone === phone)) return bad(res, email, 'Invalid credentials.');
    const flowId = id(), { code, otp } = mkOtp(flowId);
    await sendSms(u.phone, `FLASH login code: ${code}. Valid for 3 minutes. Do not share it.`);
    flows.set(flowId, { t: Date.now(), email, stage: 'otp1', otp });
    R(res, 200, { flowId, expiresIn: OTP_MS });
  },
  /* 4. login OTP -> fresh random challenge */
  'POST /api/login/otp': async (req, res, b) => {
    const f = flow(res, b, 'otp1'); if (!f) return;
    const r = checkOtp(f.otp, b.flowId, b.otp);
    if (r === 'expired') { flows.delete(b.flowId); return R(res, 400, { error: 'OTP expired or used up. Login again.' }); }
    if (r === 'wrong') return bad(res, f.email, 'Wrong OTP.');
    f.stage = 'challenge'; f.otp = null; f.nonce = crypto.randomBytes(32).toString('base64'); f.chalExp = Date.now() + CHAL_MS;
    R(res, 200, { nonce: f.nonce });
  },
  /* 5. signature made in the browser with the private key, verified here with the public key -> final 8-digit OTP */
  'POST /api/login/challenge': async (req, res, b) => {
    const f = flow(res, b, 'challenge'); if (!f) return;
    if (Date.now() > f.chalExp) { flows.delete(b.flowId); return R(res, 400, { error: 'Challenge expired. Login again.' }); }
    let ok = false;
    try {
      ok = crypto.verify('sha256', Buffer.from(f.nonce + '|' + f.email),
        { key: users[f.email].pub, dsaEncoding: 'ieee-p1363' }, Buffer.from(String(b.signature || ''), 'base64'));
    } catch (e) { ok = false; }
    if (!ok) return bad(res, f.email, 'Signature verification failed.');
    const { code, otp } = mkOtp(b.flowId);
    await sendSms(users[f.email].phone, `FLASH final code: ${code}. Valid for 3 minutes. Do not share it.`);
    f.stage = 'otp2'; f.nonce = null; f.otp = otp;                 /* challenge can never be reused */
    R(res, 200, { expiresIn: OTP_MS });
  },
  /* 6. final OTP -> session */
  'POST /api/login/final': async (req, res, b) => {
    const f = flow(res, b, 'otp2'); if (!f) return;
    const r = checkOtp(f.otp, b.flowId, b.otp);
    if (r === 'expired') { flows.delete(b.flowId); return R(res, 400, { error: 'OTP expired or used up. Login again.' }); }
    if (r === 'wrong') return bad(res, f.email, 'Wrong OTP.');
    flows.delete(b.flowId); fails.delete(f.email);
    const token = id(); sessions.set(token, { email: f.email, exp: Date.now() + SESS_MS });
    R(res, 200, { token, email: f.email, expiresIn: SESS_MS });
  },
  /* 7. protected area and logout / revoke */
  'GET /api/session': async (req, res) => { const s = authed(req, res); if (s) R(res, 200, { email: s.email, expiresIn: s.exp - Date.now() }); },
  'POST /api/logout': async (req, res) => { const s = authed(req, res); if (s) { sessions.delete(s.token); R(res, 200, { ok: true }); } }
};
function authed(req, res) {
  const t = (req.headers.authorization || '').replace('Bearer ', ''), s = sessions.get(t);
  if (!s || s.exp < Date.now()) { sessions.delete(t); R(res, 401, { error: 'Session invalid or expired.' }); return null; }
  return { email: s.email, exp: s.exp, token: t };
}

/* ---------- http server ---------- */
const server = http.createServer((req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('X-Frame-Options', 'DENY'); res.setHeader('Referrer-Policy', 'no-referrer');
  const url = req.url.split('?')[0];
  if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
    return fs.readFile(path.join(__dirname, 'public', 'index.html'), (e, d) => {
      if (e) { res.writeHead(404); return res.end('index.html not found in /public'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' }); res.end(d);
    });
  }
  const h = API[req.method + ' ' + url];
  if (!h) { res.writeHead(404); return res.end('Not found'); }
  const ip = req.socket.remoteAddress, now = Date.now(), c = hits.get(ip) || { n: 0, t: now };
  if (now - c.t > 60000) { c.n = 0; c.t = now; }
  if (++c.n > 60) { hits.set(ip, c); return R(res, 429, { error: 'Too many requests. Slow down.' }); }
  hits.set(ip, c);
  let raw = '';
  req.on('data', d => { raw += d; if (raw.length > 10000) req.destroy(); });
  req.on('end', async () => {
    let b = {}; try { b = raw ? JSON.parse(raw) : {}; } catch (e) { return R(res, 400, { error: 'Bad JSON.' }); }
    try { await h(req, res, b); }
    catch (e) { if (!e.publicMsg) console.error(e); R(res, e.publicMsg ? 502 : 500, { error: e.publicMsg || 'Server error' }); }
  });
});
setInterval(() => {
  const n = Date.now();
  for (const [k, v] of sessions) if (v.exp < n) sessions.delete(k);
  for (const [k, v] of flows) if (n - v.t > 900000) flows.delete(k);
  for (const [k, v] of pendingReg) if (n - v.t > 900000) pendingReg.delete(k);
  for (const [k, v] of hits) if (n - v.t > 120000) hits.delete(k);
}, 60000).unref();
server.listen(PORT, () => console.log(`FLASH running on http://localhost:${PORT}  (${process.env.TWILIO_SID ? 'real SMS' : 'DEV SMS: codes print here'}, ${process.env.SMTP_HOST ? 'real email' : 'DEV MAIL: keys print here'})`));
