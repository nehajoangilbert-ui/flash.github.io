# FLASH - working website (step by step)

## A. Run it on your PC (DEV mode, no accounts needed)
1. Install Node.js (LTS) from https://nodejs.org  -> check with:  node -v
2. Unzip this folder.
3. Windows: double-click START.bat      (or open terminal here and run:  node server.js)
4. Browser opens http://localhost:3000
5. OTPs and the public/private keys are PRINTED in the black terminal window.
   Copy the private key (BEGIN ... END PRIVATE KEY) from there at the challenge step.
6. Optional self-test:  node test.js

## B. Send REAL SMS + email
1. Copy .env.example to .env and fill it:
   - SMS: Twilio SID, token, from-number
   - Email: Gmail App Password (SMTP_USER / SMTP_PASS), then run:  npm install nodemailer
2. Restart:  node server.js   (terminal will say "real SMS, real email")
3. Phone must be international format: +919566038118

## C. Put it online (needs a Node host, not Netlify / GitHub Pages)
Render.com (free): push folder to GitHub -> New Web Service -> Build: (empty or npm install)
-> Start: node server.js -> add .env values under Environment. Use the https:// link.
