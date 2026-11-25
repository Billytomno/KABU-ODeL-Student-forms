// Sends through Resend (resend.com). Without RESEND_API_KEY it only logs, so development still works.
export async function send({ to, cc, subject, text }) {
  const key = process.env.RESEND_API_KEY;
  if (!key || !to) { console.log('MAIL not sent:', { to, cc, subject }); return false; }
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + key, 'Content-Type': 'application/json' },
    body: JSON.stringify({ from: process.env.MAIL_FROM, to: [].concat(to), cc: cc ? [].concat(cc) : undefined, subject, text }),
  });
  if (!r.ok) console.error('MAIL failed', r.status, await r.text());
  return r.ok;
}
