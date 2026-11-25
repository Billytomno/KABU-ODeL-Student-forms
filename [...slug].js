import bcrypt from 'bcryptjs';
import crypto from 'node:crypto';
import { sql } from '../lib/db.js';
import { session, sign, setCookie } from '../lib/auth.js';
import { send } from '../lib/mail.js';
import { ST, SCH, applic } from '../lib/rules.js';

const J = (res, c, d) => res.status(c).json(d);
const audit = (actor, action, detail) =>
  sql`insert into audit(actor,action,detail) values(${actor},${action},${JSON.stringify(detail || {})})`;
const hash = (x) => crypto.createHash('sha256').update(x).digest('hex');
const okEmail = (e) => /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e || '');
const clean = (x, n = 200) => String(x ?? '').trim().slice(0, n);

// Student sign-in. With PORTAL_AUTH_URL set, the university portal is the source of truth.
// Contract: POST {reg,password} -> 200 {ok:true,name,email}. Otherwise uses the local students table.
async function verifyStudent(reg, password) {
  if (process.env.PORTAL_AUTH_URL) {
    const r = await fetch(process.env.PORTAL_AUTH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + (process.env.PORTAL_AUTH_KEY || '') },
      body: JSON.stringify({ reg, password }),
    });
    if (!r.ok) return null;
    const d = await r.json();
    return d.ok ? { reg, name: d.name, email: d.email } : null;
  }
  const [s] = await sql`select * from students where lower(reg)=lower(${reg})`;
  return s && s.pw_hash && (await bcrypt.compare(password, s.pw_hash)) ? { reg: s.reg, name: s.name, email: s.email } : null;
}


const MAX_FAILS = 4, LOCK_MIN = 15;   // 4 wrong tries, then locked for 15 minutes
async function lockedFor(key) {       // minutes left on a lock, or 0
  const [r] = await sql`select * from login_attempts where key=${key}`;
  if (!r || !r.locked_until) return 0;
  if (new Date(r.locked_until) <= new Date()) { await sql`delete from login_attempts where key=${key}`; return 0; }
  return Math.ceil((new Date(r.locked_until) - Date.now()) / 60000);
}
async function recordFail(key) {      // returns attempts left
  const [r] = await sql`insert into login_attempts(key,fails) values(${key},1)
    on conflict (key) do update set fails=login_attempts.fails+1,
      locked_until=case when login_attempts.fails+1>=${MAX_FAILS} then now()+${LOCK_MIN + ' minutes'}::interval else null end
    returning fails`;
  return Math.max(0, MAX_FAILS - r.fails);
}
const mins = (n) => `${n} minute${n === 1 ? '' : 's'}`;

async function hodMail(station) {
  const [d] = await sql`select email from dept_email where station=${station}`;
  const [o] = await sql`select value from settings where key='odel_email'`;
  return { to: d && d.email, cc: o && o.value };
}

export default async function handler(req, res) {
  try {
    const p = req.query.slug || [], m = req.method, [a, b, c] = p, body = req.body || {};
    if (m !== 'GET' && !String(req.headers['content-type'] || '').includes('application/json'))
      return J(res, 415, { error: 'JSON only' });

    // ---------- public ----------
    if (m === 'POST' && a === 'login') {
      const { type, reg, username, password } = body;
      if (!password) return J(res, 400, { error: 'Enter your password.' });
      const isS = type === 'student', key = (isS ? 's:' : 'f:') + clean(isS ? reg : username).toLowerCase();
      const wait = await lockedFor(key);
      if (wait) return J(res, 429, { error: `Too many wrong attempts. Try again in ${mins(wait)}.`, locked: true });
      let u = null;
      if (isS) { const s = await verifyStudent(clean(reg), String(password)); if (s) u = { t: 'student', ...s }; }
      else {
        const [s] = await sql`select * from staff where username=${clean(username)}`;
        if (s && (await bcrypt.compare(String(password), s.pw_hash))) u = { t: 'staff', id: s.id, name: s.name, role: s.role, station: s.station };
      }
      if (!u) { // same message whether or not the account exists
        const left = await recordFail(key);
        return left
          ? J(res, 401, { error: `Wrong ${isS ? 'Reg. No or password' : 'username or password'}. ${left} attempt${left === 1 ? '' : 's'} left.`, attemptsLeft: left })
          : J(res, 429, { error: `Too many wrong attempts. Locked for ${mins(LOCK_MIN)}.`, locked: true });
      }
      await sql`delete from login_attempts where key=${key}`;
      setCookie(res, sign(u));
      return J(res, 200, u);
    }
    if (m === 'POST' && a === 'logout') { setCookie(res, ''); return J(res, 200, { ok: 1 }); }

    if (m === 'POST' && a === 'reset') {
      if (process.env.PORTAL_AUTH_URL) return J(res, 400, { error: 'Please reset your password on the student portal.' });
      if (b === 'request') {
        const [s] = await sql`select * from students where lower(reg)=lower(${clean(body.reg)}) and lower(email)=lower(${clean(body.email)})`;
        if (s) {
          const code = String(crypto.randomInt(100000, 1000000));
          await sql`insert into reset_codes(reg,code_hash,expires_at) values(${s.reg},${hash(code)},now()+interval '15 minutes')
                    on conflict (reg) do update set code_hash=excluded.code_hash, expires_at=excluded.expires_at`;
          await send({ to: s.email, subject: 'Kabarak University password reset code',
            text: `Your reset code is ${code}. It expires in 15 minutes. If you did not ask for it, ignore this email.` });
        }
        return J(res, 200, { ok: 1 }); // same answer either way, so nobody can probe which Reg. Nos exist
      }
      if (b === 'confirm') {
        const pw = String(body.password || '');
        if (pw.length < 8) return J(res, 400, { error: 'Password must be at least 8 characters.' });
        const rk = 'r:' + clean(body.reg).toLowerCase(), w = await lockedFor(rk);
        if (w) return J(res, 429, { error: `Too many wrong codes. Try again in ${mins(w)}.`, locked: true });
        const [r] = await sql`select * from reset_codes where lower(reg)=lower(${clean(body.reg)}) and expires_at>now()`;
        if (!r || r.code_hash !== hash(clean(body.code, 10))) {
          const left = await recordFail(rk);
          return J(res, left ? 400 : 429, { error: left ? `Wrong or expired code. ${left} attempt${left === 1 ? '' : 's'} left.` : `Too many wrong codes. Locked for ${mins(LOCK_MIN)}.` });
        }
        await sql`delete from login_attempts where key=${rk}`;
        await sql`update students set pw_hash=${await bcrypt.hash(pw, 10)} where reg=${r.reg}`;
        await sql`delete from reset_codes where reg=${r.reg}`;
        await audit(r.reg, 'password_reset');
        return J(res, 200, { ok: 1 });
      }
    }

    // ---------- everything below needs a session ----------
    const u = session(req);
    if (!u) return J(res, 401, { error: 'Sign in required' });
    const isStudent = u.t === 'student', role = u.t === 'staff' ? u.role : null;
    const R = (...r) => r.includes(role);
    const deny = () => J(res, 403, { error: 'Not allowed' });
    const id = Number(a === 'admin' ? c : b);

    if (a === 'me' && m === 'GET') return J(res, 200, u);

    // ---------- clearance ----------
    if (a === 'clearance') {
      if (m === 'POST' && !b) {
        if (!isStudent) return deny();
        const { programme, grp, school, level, mode } = body;
        if (!SCH[school]) return J(res, 400, { error: 'Choose a school' });
        const st = applic(school, level, mode);
        const [row] = await sql`insert into clearance(reg,name,programme,grp,school,level,mode)
          values(${u.reg},${u.name},${clean(programme)},${clean(grp)},${school},${clean(level)},${clean(mode)}) returning id`;
        await sql`insert into clearance_steps(clearance_id,station) select ${row.id}, unnest(${st}::int[])`;
        await audit(u.reg, 'clearance_submit', { id: row.id });
        return J(res, 201, { id: row.id, stations: st.length });
      }
      if (m === 'GET') {
        if (isStudent) return J(res, 200, await sql`
          select c.*, (select json_agg(json_build_object('station',station,'status',status,'officer',officer,'comment',comment,'at',decided_at) order by station)
                       from clearance_steps s where s.clearance_id=c.id) steps
          from clearance c where c.reg=${u.reg} order by c.id desc`);
        if (R('station', 'hod')) return J(res, 200, await sql`
          select c.id,c.name,c.reg,c.programme,c.grp from clearance c join clearance_steps s on s.clearance_id=c.id
          where s.station=${u.station} and s.status='pending' order by c.id`);
        if (R('registrar')) return J(res, 200, await sql`
          select c.id,c.name,c.reg,c.programme,c.grp from clearance c where c.registrar_at is null
          and not exists(select 1 from clearance_steps s where s.clearance_id=c.id and s.status<>'approved') order by c.id`);
        if (R('admin')) return J(res, 200, await sql`
          select c.id,c.name,c.reg,c.registrar_at,
            count(*) filter (where s.status='approved') cleared, count(*) filter (where s.status='pending') pending,
            count(*) filter (where s.status='rejected') rejected
          from clearance c join clearance_steps s on s.clearance_id=c.id group by c.id order by c.id desc limit 500`);
        return deny();
      }
      if (m === 'POST' && c === 'decide') {            // station officer or HoD clears or rejects at THEIR station
        if (!R('station', 'hod')) return deny();
        const status = body.status === 'approved' ? 'approved' : body.status === 'rejected' ? 'rejected' : null;
        if (!status) return J(res, 400, { error: 'status must be approved or rejected' });
        const r = await sql`update clearance_steps set status=${status}, officer=${u.name}, comment=${clean(body.comment, 500)}, decided_at=now()
          where clearance_id=${id} and station=${u.station} and status='pending' returning station`;
        if (!r.length) return J(res, 409, { error: 'Already decided, or not your station' });
        await audit(u.name, 'clearance_' + status, { id, station: u.station });
        return J(res, 200, { ok: 1 });
      }
      if (m === 'POST' && c === 'resubmit') {           // student asks for a re-review of a rejected station
        if (!isStudent) return deny();
        const r = await sql`update clearance_steps s set status='pending', officer=null, comment=null, decided_at=null
          from clearance c where c.id=s.clearance_id and c.id=${id} and c.reg=${u.reg} and s.station=${Number(body.station)} and s.status='rejected' returning s.station`;
        return r.length ? J(res, 200, { ok: 1 }) : J(res, 409, { error: 'Nothing to resubmit' });
      }
      if (m === 'POST' && c === 'signoff') {            // registrar, only when every station has approved
        if (!R('registrar')) return deny();
        const r = await sql`update clearance set registrar_by=${u.name}, registrar_at=now() where id=${id} and registrar_at is null
          and not exists(select 1 from clearance_steps s where s.clearance_id=clearance.id and s.status<>'approved') returning id`;
        if (!r.length) return J(res, 409, { error: 'Not all stations have cleared, or already signed' });
        await audit(u.name, 'registrar_signoff', { id });
        return J(res, 200, { ok: 1 });
      }
    }

    // ---------- missing marks ----------
    if (a === 'missing-marks') {
      if (m === 'POST' && !b) {
        if (!isStudent) return deny();
        const d = Number(body.dept_station), units = Array.isArray(body.units) ? body.units.slice(0, 5).filter((x) => clean(x.code)) : [];
        if (!ST[d] || !ST[d].startsWith('HOD') || !units.length) return J(res, 400, { error: 'Choose a department and add at least one unit' });
        const [row] = await sql`insert into missing_marks(reg,name,school,dept_station,tel) values(${u.reg},${u.name},${clean(body.school)},${d},${clean(body.tel, 30)}) returning id`;
        for (const x of units)
          await sql`insert into mm_units(mm_id,code,descr,semester,exam_type,lecturer) values(${row.id},${clean(x.code, 30)},${clean(x.descr)},${clean(x.semester)},${clean(x.exam_type, 30)},${clean(x.lecturer)})`;
        const { to, cc } = await hodMail(d);
        const emailed = await send({ to, cc, subject: `Missing Mark Request - ${u.reg}`,
          text: `Dear HoD, ${ST[d].slice(5)},\n\nA missing mark request was submitted.\n\nStudent: ${u.name} (${u.reg})\nTel: ${clean(body.tel, 30)}\n\nUnits:\n` +
            units.map((x) => `- ${clean(x.code, 30)} ${clean(x.descr)} | ${clean(x.semester)} | ${clean(x.exam_type, 30)} | Lecturer: ${clean(x.lecturer)}`).join('\n') +
            '\n\nPlease review and finalise it in the online system.' });
        await audit(u.reg, 'mm_submit', { id: row.id, emailed });
        return J(res, 201, { id: row.id, emailed });
      }
      if (m === 'GET') {
        if (isStudent) return J(res, 200, await sql`select * from mm_full where reg=${u.reg} order by id desc`);
        if (R('hod')) return J(res, 200, await sql`select * from mm_full where status='pending' and dept_station=${u.station} order by id`);
        if (R('odel', 'admin')) return J(res, 200, await sql`select * from mm_full order by id desc limit 500`);
        return deny();
      }
      if (m === 'POST' && c === 'finalise') {           // only the HoD of that department
        if (!R('hod')) return deny();
        const [r] = await sql`select * from missing_marks where id=${id} and dept_station=${u.station} and status='pending'`;
        if (!r) return J(res, 409, { error: 'Not found, already final, or not your department' });
        for (const x of body.units || [])
          await sql`update mm_units set cat_mark=${clean(x.cat, 20)}, exam_mark=${clean(x.exam, 20)}, examiner_sig=${clean(x.sig, 80)} where id=${Number(x.id)} and mm_id=${id}`;
        await sql`update missing_marks set status='final', fin_by=${u.name}, fin_at=now(), outcome=${clean(body.outcome)}, remarks=${clean(body.remarks, 500)} where id=${id}`;
        const [s] = await sql`select email from students where reg=${r.reg}`;
        await send({ to: s && s.email, subject: 'Your missing mark request has been finalised',
          text: `Dear ${r.name},\n\nYour missing mark request (#${id}) was finalised by ${u.name}.\nOutcome: ${clean(body.outcome)}\n${clean(body.remarks, 500)}\n\nSign in to view the details.` });
        await audit(u.name, 'mm_finalise', { id });
        return J(res, 200, { ok: 1 });
      }
    }

    // ---------- admin ----------
    if (a === 'admin') {
      if (!R('admin')) return deny();
      if (b === 'staff' && m === 'GET') return J(res, 200, await sql`select id,username,name,email,role,station from staff order by id`);
      if (b === 'staff' && m === 'POST') {
        const { username, name, password, role: r, station, email } = body;
        if (!clean(username) || !clean(name) || String(password || '').length < 10) return J(res, 400, { error: 'Username, name and a 10+ character password are required' });
        if (!['station', 'hod', 'odel', 'registrar', 'admin'].includes(r)) return J(res, 400, { error: 'Bad role' });
        if ((r === 'station' || r === 'hod') && !ST[Number(station)]) return J(res, 400, { error: 'Station required' });
        if (r === 'hod' && !ST[Number(station)].startsWith('HOD')) return J(res, 400, { error: 'A HoD must be assigned to a HOD department' });
        await sql`insert into staff(username,name,email,pw_hash,role,station) values(${clean(username)},${clean(name)},${clean(email)},${await bcrypt.hash(String(password), 10)},${r},${r === 'station' || r === 'hod' ? Number(station) : null})`;
        await audit(u.name, 'staff_add', { username, role: r, station });
        return J(res, 201, { ok: 1 });
      }
      if (b === 'staff' && m === 'DELETE') {
        if (id === u.id) return J(res, 400, { error: 'You cannot remove yourself' });
        await sql`delete from staff where id=${id}`;
        await audit(u.name, 'staff_remove', { id });
        return J(res, 200, { ok: 1 });
      }
      if (b === 'students' && m === 'POST') {         // pilot only: bulk-load students when no portal is connected
        let n = 0;
        for (const s of (body.students || []).slice(0, 2000)) {
          if (!clean(s.reg) || !okEmail(s.email)) continue;
          await sql`insert into students(reg,name,email,pw_hash) values(${clean(s.reg)},${clean(s.name)},${clean(s.email)},${s.password ? await bcrypt.hash(String(s.password), 10) : null})
                    on conflict (reg) do update set name=excluded.name, email=excluded.email`;
          n++;
        }
        return J(res, 200, { imported: n });
      }
      if (b === 'settings' && m === 'GET') return J(res, 200, {
        odel_email: ((await sql`select value from settings where key='odel_email'`)[0] || {}).value || '',
        dept: await sql`select station,email from dept_email order by station` });
      if (b === 'settings' && m === 'PUT') {
        if (body.odel_email !== undefined) {
          if (body.odel_email && !okEmail(body.odel_email)) return J(res, 400, { error: 'Bad ODeL email' });
          await sql`insert into settings(key,value) values('odel_email',${clean(body.odel_email)}) on conflict (key) do update set value=excluded.value`;
        }
        for (const [st, em] of Object.entries(body.dept || {})) {
          if (!ST[Number(st)] || !ST[Number(st)].startsWith('HOD')) continue;
          if (!em) await sql`delete from dept_email where station=${Number(st)}`;
          else if (okEmail(em)) await sql`insert into dept_email(station,email) values(${Number(st)},${em}) on conflict (station) do update set email=excluded.email`;
        }
        await audit(u.name, 'settings_update');
        return J(res, 200, { ok: 1 });
      }
    }
    return J(res, 404, { error: 'Not found' });
  } catch (e) {
    console.error(e);
    return J(res, 500, { error: 'Server error' });
  }
}
