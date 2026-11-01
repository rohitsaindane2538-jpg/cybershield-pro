// Static file triage. Never executes the file; only reads bytes.
const crypto = require('crypto');
const hash = (alg, buf) => crypto.createHash(alg).update(buf).digest('hex');
const MAGIC = [
  [[0x4d, 0x5a], 'Windows executable (PE)', true], [[0x7f, 0x45, 0x4c, 0x46], 'Linux executable (ELF)', true],
  [[0xcf, 0xfa, 0xed, 0xfe], 'macOS executable (Mach-O)', true], [[0x50, 0x4b, 0x03, 0x04], 'ZIP / Office / JAR archive'],
  [[0x25, 0x50, 0x44, 0x46], 'PDF document'], [[0x23, 0x21], 'Script (shebang)', true], [[0xd0, 0xcf, 0x11, 0xe0], 'Legacy Office (OLE)'],
  [[0x52, 0x61, 0x72, 0x21], 'RAR archive'], [[0x89, 0x50, 0x4e, 0x47], 'PNG image'], [[0xff, 0xd8, 0xff], 'JPEG image']
];
function entropy(buf) {
  if (!buf.length) return 0; const f = new Array(256).fill(0); for (const b of buf) f[b]++;
  return Math.max(0, -f.reduce((s, n) => n ? s + (n / buf.length) * Math.log2(n / buf.length) : s, 0));
}
function inspect(buf, name = 'file') {
  const head = [...buf.subarray(0, 8)];
  const m = MAGIC.find(([sig]) => sig.every((b, i) => head[i] === b));
  const type = m ? m[1] : 'Unknown or plain data', executable = !!(m && m[2]);
  const ent = entropy(buf), strs = (buf.toString('latin1').match(/[\x20-\x7e]{6,}/g) || []);
  const text = strs.join('\n'), flags = []; let score = 0;
  const add = (w, f) => { score += w; flags.push(f); };
  if (executable) add(20, `Executable content (${type})`);
  if (ent > 7.2 && buf.length > 2048) add(20, `Very high entropy (${ent.toFixed(2)}): packed or encrypted data`);
  if (/\.(pdf|docx?|xlsx?|jpe?g|png|txt|csv)\.(exe|scr|js|vbs|bat|cmd|ps1|jar)$/i.test(name)) add(30, 'Double extension disguises an executable');
  if (/\.(jpe?g|png|pdf|txt|docx?|xlsx?)$/i.test(name) && executable) add(35, 'File extension does not match its real type (masquerading)');
  if (/VirtualAlloc|CreateRemoteThread|WriteProcessMemory|NtUnmapViewOfSection/.test(text)) add(25, 'Process injection API strings');
  if (/powershell(\.exe)?\s+-(enc|e|w hidden)|cmd(\.exe)?\s+\/c|FromBase64String/i.test(text)) add(20, 'Encoded or hidden command execution strings');
  if (/vbaProject\.bin|AutoOpen|Document_Open|Auto_Open/.test(buf.toString('latin1'))) add(25, 'Office macro indicators');
  if (/https?:\/\/\d{1,3}(\.\d{1,3}){3}/.test(text)) add(10, 'Embedded URL with raw IP address');
  return {
    meta: { name, size: buf.length, type, entropy: +ent.toFixed(2), sha256: hash('sha256', buf), sha1: hash('sha1', buf), md5: hash('md5', buf), stringsSample: strs.slice(0, 60) },
    score: Math.min(100, score), flags, stringsText: text.slice(0, 4000)
  };
}
module.exports = { inspect, entropy };
