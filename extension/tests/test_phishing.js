const fs = require('fs');
const assert = require('assert');

// Load phishing.js
const code = fs.readFileSync('extension/lib/phishing.js', 'utf8');
eval(code);

console.log('[*] Testing FerroShieldPhishing with eTLD+1 parser...');

// Test 1: parseDomain accuracy
const casesDomain = [
  { host: 'cekbansos.kemensos.go.id', etld: 'go.id', etldPlusOne: 'kemensos.go.id', mainLabel: 'kemensos', subdomains: ['cekbansos'] },
  { host: 'simaster.ugm.ac.id', etld: 'ac.id', etldPlusOne: 'ugm.ac.id', mainLabel: 'ugm', subdomains: ['simaster'] },
  { host: 'www.bca.co.id', etld: 'co.id', etldPlusOne: 'bca.co.id', mainLabel: 'bca', subdomains: [] },
  { host: 'sub.sub2.example.com.au', etld: 'com.au', etldPlusOne: 'example.com.au', mainLabel: 'example', subdomains: ['sub', 'sub2'] },
  { host: 'bca.co.id.login-verify.top', etld: 'top', etldPlusOne: 'login-verify.top', mainLabel: 'login-verify', subdomains: ['bca', 'co', 'id'] },
  { host: 'myproject.github.io', etld: 'github.io', etldPlusOne: 'myproject.github.io', mainLabel: 'myproject', subdomains: [] }
];

for (const c of casesDomain) {
  const res = FerroShieldPhishing.parseDomain(c.host);
  assert.strictEqual(res.etld, c.etld, `eTLD mismatch for ${c.host}: expected ${c.etld}, got ${res.etld}`);
  assert.strictEqual(res.etldPlusOne, c.etldPlusOne, `eTLD+1 mismatch for ${c.host}: expected ${c.etldPlusOne}, got ${res.etldPlusOne}`);
  assert.strictEqual(res.mainLabel, c.mainLabel, `mainLabel mismatch for ${c.host}: expected ${c.mainLabel}, got ${res.mainLabel}`);
  assert.deepStrictEqual(res.subdomains, c.subdomains, `subdomains mismatch for ${c.host}: expected ${JSON.stringify(c.subdomains)}, got ${JSON.stringify(res.subdomains)}`);
  console.log(`  [+] parseDomain passed: ${c.host} -> eTLD+1: ${res.etldPlusOne}`);
}

// Test 2: Legitimate government & education sites must have score = 0 (NOT blocked)
const legitSites = [
  'https://cekbansos.kemensos.go.id/',
  'https://prakerja.go.id',
  'https://layanan.kominfo.go.id/portal',
  'https://polri.go.id',
  'https://kemkes.go.id',
  'https://simaster.ugm.ac.id',
  'https://itb.ac.id',
  'https://smkn1jakarta.sch.id',
  'https://desaku.desa.id',
  'https://klikbca.com',
  'https://m.klikbca.com',
  'https://www.bca.co.id',
  'https://google.co.id',
  'https://tokopedia.com',
  'https://shopee.co.id'
];

for (const url of legitSites) {
  const res = FerroShieldPhishing.evaluate(url);
  assert.strictEqual(res.score < 50, true, `Legitimate site ${url} blocked! Score: ${res.score}, Reasons: ${res.reasons.join(', ')}`);
  console.log(`  [+] Legit passed (Score ${res.score}): ${url}`);
}

// Test 3: Obvious Phishing / Malicious Scam sites must be blocked (score >= 50)
const phishSites = [
  'https://bca.co.id.login-verify.top/',
  'https://paypal.com.account-update.xyz/',
  'https://paypa1.com/login',
  'https://tokopedla.com/verify',
  'https://bca-klik.top/login',
  'http://192.168.1.100/login/password',
  'https://mypertamina.com.promo-undian.online/hadiah'
];

for (const url of phishSites) {
  const res = FerroShieldPhishing.evaluate(url);
  assert.strictEqual(res.score >= 50, true, `Phishing site ${url} NOT blocked! Score: ${res.score}, Reasons: ${res.reasons.join(', ')}`);
  console.log(`  [+] Phishing detected (Score ${res.score}): ${url} -> Reasons: ${res.reasons.join('; ')}`);
}

console.log('\n[+] ALL PHISHING & eTLD+1 TESTS PASSED SUCCESSFULLY!');
