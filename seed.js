// usage: DATABASE_URL=... node scripts/seed.js <username> <password> "<Full name>"
import bcrypt from 'bcryptjs';
import { sql } from '../lib/db.js';
const [u, p, n = 'Administrator'] = process.argv.slice(2);
if (!u || !p || p.length < 10) { console.log('Give a username and a password of 10+ characters'); process.exit(1); }
await sql`insert into staff(username,name,pw_hash,role) values(${u},${n},${await bcrypt.hash(p, 10)},'admin')
          on conflict (username) do update set pw_hash=excluded.pw_hash, role='admin'`;
console.log('Admin ready:', u);
