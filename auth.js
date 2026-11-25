import crypto from 'node:crypto';
const mac = (b) => crypto.createHmac('sha256', process.env.SESSION_SECRET).update(b).digest('base64url');
export function sign(p) {
  const body = Buffer.from(JSON.stringify({ ...p, exp: Date.now() + 8 * 36e5 })).toString('base64url');
  return body + '.' + mac(body);
}
export function verify(t) {
  if (!t || !process.env.SESSION_SECRET) return null;
  const [body, sig] = t.split('.'), ok = body && mac(body);
  if (!sig || sig.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(ok))) return null;
  const p = JSON.parse(Buffer.from(body, 'base64url'));
  return p.exp > Date.now() ? p : null;
}
export const session = (req) => { const m = (req.headers.cookie || '').match(/(?:^|; )kabu=([^;]+)/); return verify(m && m[1]); };
export const setCookie = (res, t) =>
  res.setHeader('Set-Cookie', `kabu=${t || ''}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${t ? 28800 : 0}`);
