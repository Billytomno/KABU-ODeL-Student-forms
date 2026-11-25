# Kabarak University – Online Clearance & Missing Mark System (Vercel)

## What is here
- `public/index.html` – the front-end (still the DEMO version that stores data in the browser; see "Next step").
- `api/[...slug].js` – the whole back-end: sign-in, clearance, missing marks, admin, e-mail.
- `lib/` – database, session cookies, e-mail, station rules (`rules.js` decides which stations apply to a student).
- `schema.sql` – database tables. `scripts/seed.js` – creates the first administrator.

## Deploy in 6 steps
1. Push this folder to a GitHub repository.
2. Vercel → Add New → Project → import the repo → Deploy (no build settings needed).
3. Project → Storage → add **Neon Postgres** (or any Postgres). This sets `DATABASE_URL`.
4. Open the database's SQL editor, paste `schema.sql`, run it.
5. Project → Settings → Environment Variables, add `SESSION_SECRET` (long random text), and for e-mail
   `RESEND_API_KEY` + `MAIL_FROM` (a Resend-verified Kabarak address). Redeploy.
6. Create the first admin from your computer:
   `npm i && DATABASE_URL="..." node scripts/seed.js admin "a-long-password" "Your Name"`

Then sign in as admin, add the HoD e-mails and the Director ODeL e-mail (PUT /api/admin/settings), and create staff.

## Student sign-in
- **Live:** set `PORTAL_AUTH_URL` (+ `PORTAL_AUTH_KEY`). The back-end POSTs `{reg,password}` to it and expects
  `200 {"ok":true,"name":"...","email":"..."}`. Ask Kabarak ICT to provide such an endpoint (or tell us how the portal logs in
  and the adapter in `verifyStudent` is the only code that changes). Password resets then happen on the portal.
- **Pilot without the portal:** leave it empty, load students with POST /api/admin/students, and the built-in
  reset-by-student-email flow works (needs Resend).

## API (all JSON; the session is an HttpOnly cookie)
| Who | Call |
|---|---|
| anyone | POST /api/login `{type:'student',reg,password}` or `{type:'staff',username,password}`; POST /api/logout; POST /api/reset/request `{reg,email}`; POST /api/reset/confirm `{reg,code,password}` |
| student | POST /api/clearance `{programme,grp,school,level,mode}`; GET /api/clearance (own, with steps); POST /api/clearance/:id/resubmit `{station}`; POST /api/missing-marks `{school,dept_station,tel,units:[{code,descr,semester,exam_type,lecturer}]}`; GET /api/missing-marks (own) |
| station officer / HoD | GET /api/clearance (their station's pending); POST /api/clearance/:id/decide `{status:'approved'|'rejected',comment}` |
| HoD | GET /api/missing-marks (their department's pending); POST /api/missing-marks/:id/finalise `{units:[{id,cat,exam,sig}],outcome,remarks}` |
| Registrar | GET /api/clearance (ready to sign); POST /api/clearance/:id/signoff |
| Director ODeL | GET /api/missing-marks (all, read-only) |
| admin | GET/POST/DELETE /api/admin/staff(/:id); POST /api/admin/students; GET/PUT /api/admin/settings; GET /api/clearance (overview) |

Security built in: roles enforced on the server (an officer can only act on their own station, a HoD only on their own
department, a student only sees their own records), bcrypt-hashed passwords, signed HttpOnly cookies, JSON-only writes,
an audit log table, and the same answer for known and unknown Reg. Nos on reset.

## Next step (not done yet)
`public/index.html` must be switched from browser storage to these endpoints (replace the `D.*` reads/writes with `fetch('/api/...')`).
Still to add before going live: network-level rate limiting (e.g. Vercel Firewall) and a Data Protection Act review of what is stored.

Login limits: 4 wrong passwords (or 4 wrong reset codes) lock that account for 15 minutes; the message shows attempts left.
Change `MAX_FAILS` / `LOCK_MIN` at the top of `api/[...slug].js`.
