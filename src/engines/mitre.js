// Curated MITRE ATT&CK subset. AI-suggested IDs are validated against this table so hallucinated IDs never reach the UI.
const TECHNIQUES = {
  T1566: 'Phishing', T1204: 'User Execution', T1110: 'Brute Force', T1078: 'Valid Accounts', T1190: 'Exploit Public-Facing Application',
  T1059: 'Command and Scripting Interpreter', T1027: 'Obfuscated Files or Information', T1055: 'Process Injection', T1552: 'Unsecured Credentials',
  T1595: 'Active Scanning', T1189: 'Drive-by Compromise', T1056: 'Input Capture', T1071: 'Application Layer Protocol', T1105: 'Ingress Tool Transfer',
  T1036: 'Masquerading', T1003: 'OS Credential Dumping', T1505: 'Server Software Component', T1083: 'File and Directory Discovery',
  T1041: 'Exfiltration Over C2 Channel', T1486: 'Data Encrypted for Impact'
};
const KEYWORDS = [
  [/brute force|failed or denied/i, 'T1110'], [/sql injection|traversal|public-facing/i, 'T1190'], [/xss|command|eval|execution/i, 'T1059'],
  [/scanning tool/i, 'T1595'], [/urgency|credentials|sensitive data|shortened|raw ip|prize|scam|lookalike|punycode|impersonat/i, 'T1566'],
  [/hard-coded secret/i, 'T1552'], [/entropy|packed|obfuscat/i, 'T1027'], [/injection api|virtualalloc|remotethread/i, 'T1055'],
  [/double extension|mismatch|masquerad/i, 'T1036'], [/macro/i, 'T1204']
];
const entry = id => ({ id, name: TECHNIQUES[id] });
function fromFlags(flags = []) {
  const ids = new Set(); flags.forEach(f => KEYWORDS.forEach(([re, id]) => re.test(f) && ids.add(id))); return [...ids].map(entry);
}
function validate(list) {
  if (!Array.isArray(list)) return [];
  const ids = new Set(list.map(x => String(x?.id ?? x).toUpperCase()).filter(id => TECHNIQUES[id]));
  return [...ids].slice(0, 6).map(entry);
}
module.exports = { TECHNIQUES, fromFlags, validate, entry };
