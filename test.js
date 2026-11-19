// Run: node test.js   (starts the server in dev mode on port 3999 and runs the whole flow)
const { spawn } = require('child_process'), crypto = require('crypto'), path = require('path');
const srv = spawn('node', ['server.js'], { cwd: __dirname, env: { ...process.env, PORT: 3999, TWILIO_SID: '', SMTP_HOST: '' } });
let out = ''; srv.stdout.on('data', d => out += d); srv.stderr.on('data', d => out += d);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const call = async (m, p, b, tok) => { const r = await fetch('http://localhost:3999' + p, { method: m, headers: { 'Content-Type': 'application/json', ...(tok ? { Authorization: 'Bearer ' + tok } : {}) }, body: b ? JSON.stringify(b) : undefined }); return { s: r.status, j: await r.json() }; };
const lastOtp = () => { const m = [...out.matchAll(/code: (\d{8})/g)]; return m[m.length - 1][1]; };
let ok = true; const check = (n, c) => { console.log((c ? 'PASS ' : 'FAIL ') + n); if (!c) ok = false; };
(async () => {
  await sleep(800);
  const email = 'a@b.com', phone = '+919566038118', password = 'Strong#Pass1';
  let r = await call('POST', '/api/register', { email, phone, password }); check('register sends OTP', r.s === 200);
  const regId = r.j.regId; await sleep(100);
  r = await call('POST', '/api/register/verify', { regId, otp: lastOtp() }); check('phone OTP verifies + keys emailed', r.s === 200 && /PRIVATE KEY/.test(out));
  const prv = out.match(/-----BEGIN PRIVATE KEY-----[\s\S]*?-----END PRIVATE KEY-----/)[0];
  r = await call('POST', '/api/login', { email, phone, password: 'wrong' }); check('wrong password rejected', r.s === 401);
  r = await call('POST', '/api/login', { email, phone, password }); check('login sends OTP', r.s === 200);
  const flowId = r.j.flowId; await sleep(100);
  r = await call('POST', '/api/login/otp', { flowId, otp: lastOtp() }); check('login OTP -> challenge', r.s === 200 && r.j.nonce);
  const nonce = r.j.nonce;
  const bad = await call('POST', '/api/login/challenge', { flowId, signature: 'AAAA' }); check('bad signature rejected', bad.s === 401);
  const sig = crypto.sign('sha256', Buffer.from(nonce + '|' + email), { key: prv, dsaEncoding: 'ieee-p1363' }).toString('base64');
  r = await call('POST', '/api/login/challenge', { flowId, signature: sig }); check('good signature -> final OTP', r.s === 200);
  r = await call('POST', '/api/login/challenge', { flowId, signature: sig }); check('replayed signature rejected', r.s === 400);
  await sleep(100);
  r = await call('POST', '/api/login/final', { flowId, otp: lastOtp() }); check('final OTP -> session', r.s === 200 && r.j.token);
  const token = r.j.token;
  r = await call('GET', '/api/session', null, token); check('session valid', r.s === 200 && r.j.email === email);
  r = await call('POST', '/api/logout', {}, token); r = await call('GET', '/api/session', null, token); check('revoked token rejected', r.s === 401);
  let locked = false; for (let i = 0; i < 7; i++) { r = await call('POST', '/api/login', { email, phone, password: 'nope' + i }); if (r.s === 423) { locked = true; break; } }
  check('locked after more than 5 wrong attempts', locked);
  r = await call('POST', '/api/login', { email, phone, password }); check('correct password still blocked while locked', r.s === 423);
  srv.kill(); require('fs').rmSync(path.join(__dirname, 'users.json'), { force: true });
  console.log(ok ? '\nALL TESTS PASSED' : '\nSOME TESTS FAILED'); process.exit(ok ? 0 : 1);
})();
