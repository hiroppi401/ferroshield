/* FerroShield Browser Guard - heuristik phishing/scam lokal dengan eTLD+1 parser.
 * Skor 0-100; skor >= 50 memicu halaman peringatan. Desain agar ringan:
 * tidak ada I/O, murni komputasi string per navigasi utama.
 */
(function () {
  'use strict';

  var BRANDS = [
    'paypal', 'facebook', 'instagram', 'whatsapp', 'google', 'gmail',
    'apple', 'icloud', 'microsoft', 'outlook', 'office365', 'netflix',
    'amazon', 'ebay', 'shopify', 'binance', 'coinbase', 'metamask',
    'steam', 'epicgames', 'riotgames', 'discord', 'telegram', 'tiktok',
    'twitter', 'linkedin', 'reddit',
    'bca', 'mandiri', 'bni', 'bri', 'dana', 'ovo', 'gopay', 'gojek',
    'tokopedia', 'shopee', 'lazada', 'bukalapak', 'blibli',
    'telkomsel', 'indihome', 'mypertamina'
  ];

  var BRAND_OFFICIAL = {
    'paypal': ['paypal.com'], 'facebook': ['facebook.com'],
    'instagram': ['instagram.com'], 'whatsapp': ['whatsapp.com'],
    'google': ['google.com', 'google.co.id'], 'gmail': ['gmail.com'],
    'apple': ['apple.com'], 'icloud': ['icloud.com'],
    'microsoft': ['microsoft.com'], 'outlook': ['outlook.com'],
    'office365': ['office.com', 'office365.com'],
    'netflix': ['netflix.com'], 'amazon': ['amazon.com'],
    'ebay': ['ebay.com'], 'shopify': ['shopify.com'],
    'binance': ['binance.com'], 'coinbase': ['coinbase.com'],
    'metamask': ['metamask.io'],
    'steam': ['steampowered.com'], 'epicgames': ['epicgames.com'],
    'riotgames': ['riotgames.com'], 'discord': ['discord.com'],
    'telegram': ['telegram.org'], 'tiktok': ['tiktok.com'],
    'twitter': ['twitter.com', 'x.com'], 'linkedin': ['linkedin.com'],
    'reddit': ['reddit.com'],
    'bca': ['bca.co.id', 'klikbca.com'],
    'mandiri': ['bankmandiri.co.id'],
    'bni': ['bni.co.id'], 'bri': ['bri.co.id'],
    'dana': ['dana.id'], 'ovo': ['ovo.id'],
    'gopay': ['gopay.co.id'], 'gojek': ['gojek.com'],
    'tokopedia': ['tokopedia.com'], 'shopee': ['shopee.co.id'],
    'lazada': ['lazada.co.id'], 'bukalapak': ['bukalapak.com'],
    'blibli': ['blibli.com'], 'telkomsel': ['telkomsel.com'],
    'indihome': ['indihome.net'], 'mypertamina': ['mypertamina.id']
  };

  var SUSPICIOUS_TLDS = new Set([
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online',
    '.site', '.work', '.stream', '.download', '.review', '.bid', '.trade',
    '.men', '.loan', '.zip', '.country', '.click', '.link', '.surf',
    '.rest', '.bar', '.cam', '.live', '.life', '.kim', '.icu', '.gdn',
    '.buzz', '.host', '.space', '.press', '.fun', '.vip', '.win',
    '.wang', '.science', '.party', '.racing', '.faith', '.date',
    '.webcam', '.accountant', '.stream', '.monster', '.skin', '.quest',
    '.cricket', '.golf', '.jewelry'
  ]);

  var SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'sign-in', 'verify', 'verification', 'secure',
    'account', 'confirm', 'update', 'unlock', 'recover', 'wallet',
    'bitcoin', 'crypto', 'prize', 'lottery', 'reward', 'bonus',
    'support', 'auth', 'credential', 'password', '2fa', 'otp',
    'refund', 'invoice', 'billing', 'password-reset', 'reset-password',
    'security-alert', 'suspended', 'blocked', 'unusual', 'kode',
    'verifikasi', 'hadiah', 'undian', 'perpanjangan', 'tidak-aktif',
    'pembayaran'
  ];

  // Daftar Public Suffix (eTLD) komprehensif untuk Indonesia & internasional
  var PUBLIC_SUFFIXES = new Set([
    // Indonesia (ccSLDs)
    'go.id', 'ac.id', 'co.id', 'or.id', 'mil.id', 'net.id', 'web.id',
    'sch.id', 'desa.id', 'my.id', 'biz.id', 'ponpes.id', 'ppni.id',
    // United Kingdom
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'net.uk', 'me.uk', 'ltd.uk', 'plc.uk',
    // Australia & New Zealand
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au', 'asn.au', 'id.au',
    'co.nz', 'net.nz', 'org.nz', 'govt.nz', 'ac.nz', 'school.nz',
    // Asia-Pacific
    'co.jp', 'ne.jp', 'or.jp', 'ac.jp', 'go.jp', 'ed.jp', 'lg.jp',
    'com.sg', 'net.sg', 'org.sg', 'gov.sg', 'edu.sg', 'per.sg',
    'com.my', 'net.my', 'org.my', 'gov.my', 'edu.my', 'mil.my',
    'co.th', 'ac.th', 'go.th', 'or.th', 'net.th', 'in.th',
    'com.ph', 'net.ph', 'org.ph', 'gov.ph', 'edu.ph',
    'com.vn', 'net.vn', 'org.vn', 'edu.vn', 'gov.vn', 'biz.vn',
    'co.in', 'net.in', 'org.in', 'gen.in', 'ac.in', 'edu.in', 'res.in', 'gov.in',
    'com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn', 'ac.cn',
    'co.kr', 'ne.kr', 'or.kr', 're.kr', 'pe.kr', 'go.kr', 'ac.kr',
    'com.tw', 'net.tw', 'org.tw', 'idv.tw', 'edu.tw', 'gov.tw',
    'com.hk', 'edu.hk', 'gov.hk', 'idv.hk', 'net.hk', 'org.hk',
    // Americas
    'com.br', 'net.br', 'org.br', 'gov.br', 'edu.br', 'jus.br', 'leg.br', 'mp.br',
    'com.mx', 'net.mx', 'org.mx', 'edu.mx', 'gob.mx',
    'com.ar', 'net.ar', 'org.ar', 'gob.ar', 'gov.ar', 'edu.ar',
    // Middle East & Africa & Europe
    'com.tr', 'net.tr', 'org.tr', 'gov.tr', 'edu.tr', 'bel.tr',
    'co.za', 'net.za', 'org.za', 'gov.za', 'ac.za', 'edu.za',
    'com.eg', 'edu.eg', 'gov.eg', 'net.eg', 'org.eg',
    'com.sa', 'edu.sa', 'gov.sa', 'net.sa', 'org.sa',
    'com.ua', 'edu.ua', 'gov.ua', 'net.ua', 'org.ua',
    'com.ru', 'net.ru', 'org.ru', 'gov.ru', 'edu.ru',
    'co.il', 'org.il', 'net.il', 'ac.il', 'gov.il',
    'com.pk', 'net.pk', 'org.pk', 'edu.pk', 'gov.pk',
    'com.bd', 'edu.bd', 'net.bd', 'gov.bd', 'org.bd',
    'co.ke', 'or.ke', 'ne.ke', 'go.ke', 'ac.ke',
    'com.ng', 'org.ng', 'gov.ng', 'edu.ng', 'net.ng',
    'com.gh', 'edu.gh', 'gov.gh', 'org.gh', 'net.gh',
    // Popular Public SaaS/Hosting (subdomain separation)
    'github.io', 'gitlab.io', 'vercel.app', 'netlify.app', 'pages.dev',
    'firebaseapp.com', 'web.app', 'herokuapp.com', 'azurewebsites.net'
  ]);

  function levenshtein(a, b) {
    var m = a.length, n = b.length;
    if (m === 0) return n;
    if (n === 0) return m;
    var prev = new Array(n + 1);
    var curr = new Array(n + 1);
    for (var j = 0; j <= n; j++) { prev[j] = j; }
    for (var i = 1; i <= m; i++) {
      curr[0] = i;
      for (var j = 1; j <= n; j++) {
        var cost = a[i - 1] === b[j - 1] ? 0 : 1;
        curr[j] = Math.min(prev[j] + 1, curr[j - 1] + 1, prev[j - 1] + cost);
      }
      var tmp = prev; prev = curr; curr = tmp;
    }
    return prev[n];
  }

  /**
   * Mengekstrak eTLD (public suffix), eTLD+1 (registered domain), mainLabel, dan subdomain.
   * Contoh: "cekbansos.kemensos.go.id"
   * -> etld: "go.id", etldPlusOne: "kemensos.go.id", mainLabel: "kemensos", subdomains: ["cekbansos"]
   */
  function parseDomain(host) {
    if (!host) return null;
    var labels = host.toLowerCase().split('.');
    if (labels.length === 0) return null;

    var suffix = '';
    var suffixLen = 1;

    if (labels.length >= 3) {
      var s3 = labels.slice(-3).join('.');
      if (PUBLIC_SUFFIXES.has(s3)) {
        suffix = s3;
        suffixLen = 3;
      }
    }
    if (!suffix && labels.length >= 2) {
      var s2 = labels.slice(-2).join('.');
      if (PUBLIC_SUFFIXES.has(s2)) {
        suffix = s2;
        suffixLen = 2;
      }
    }
    if (!suffix) {
      suffix = labels[labels.length - 1];
      suffixLen = 1;
    }

    if (labels.length <= suffixLen) {
      return {
        hostname: host,
        etld: suffix,
        etldPlusOne: host,
        mainLabel: host,
        subdomains: []
      };
    }

    var mainLabel = labels[labels.length - suffixLen - 1];
    var etldPlusOne = mainLabel + '.' + suffix;
    var rawSubdomains = labels.slice(0, labels.length - suffixLen - 1);
    var subdomains = [];
    for (var i = 0; i < rawSubdomains.length; i++) {
      if (i === 0 && rawSubdomains[i] === 'www') {
        continue;
      }
      subdomains.push(rawSubdomains[i]);
    }

    return {
      hostname: host,
      etld: suffix,
      etldPlusOne: etldPlusOne,
      mainLabel: mainLabel,
      subdomains: subdomains
    };
  }

  function evaluate(rawUrl) {
    var url;
    try {
      url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(rawUrl) ? rawUrl : 'https://' + rawUrl);
    } catch (e) {
      return { score: 0, reasons: [] };
    }
    var host = url.hostname.toLowerCase();
    if (!host || host === 'localhost' || host === '127.0.0.1' || host === '::1') {
      return { score: 0, reasons: [] };
    }

    var score = 0;
    var reasons = [];

    // 1. Literal IP host
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      score += 35;
      reasons.push('Host berupa IP literal');
    }

    // 2. Punycode / IDN Homograph
    if (host.indexOf('xn--') === 0 || host.indexOf('.xn--') !== -1) {
      score += 30;
      reasons.push('Punycode / homograph');
    }

    // 3. Ekstraksi eTLD+1
    var parsed = parseDomain(host);
    if (!parsed) {
      return { score: 0, reasons: [] };
    }

    var etld = parsed.etld;
    var etldPlusOne = parsed.etldPlusOne;
    var mainLabel = parsed.mainLabel;
    var subdomains = parsed.subdomains;
    var subdomainStr = subdomains.join('.');

    // 4. Suspicious TLD
    // Cek suffix paling akhir (misal .xyz atau .top)
    var topLevel = '.' + host.split('.').pop();
    if (SUSPICIOUS_TLDS.has(topLevel) || SUSPICIOUS_TLDS.has('.' + etld)) {
      score += 30;
      reasons.push('TLD mencurigakan: ' + (SUSPICIOUS_TLDS.has('.' + etld) ? '.' + etld : topLevel));
    }

    // 5. Kata kunci mencurigakan dalam URL / host
    var checkStr = (host + (url.pathname ? url.pathname.toLowerCase() : ''));
    var keywordHit = null;
    for (var k = 0; k < SUSPICIOUS_KEYWORDS.length; k++) {
      var kw = SUSPICIOUS_KEYWORDS[k];
      if (checkStr.indexOf(kw) !== -1) {
        keywordHit = kw;
        break;
      }
    }
    if (keywordHit) {
      score += 18;
      reasons.push('Kata kunci mencurigakan: ' + keywordHit);
    }

    // 6. Evaluasi Brand & Typosquatting berbasis eTLD+1
    for (var b = 0; b < BRANDS.length; b++) {
      var brand = BRANDS[b];
      var officialList = BRAND_OFFICIAL[brand] || [];

      // A. Jika hostname atau eTLD+1 terdaftar resmi di whitelist brand
      if (officialList.indexOf(etldPlusOne) !== -1 || officialList.indexOf(host) !== -1) {
        return { score: 0, reasons: [] };
      }

      // B. Subdomain Brand Impersonation (misal: bca.co.id.login-verify.top)
      if (subdomains.length > 0 && subdomainStr.indexOf(brand) !== -1) {
        score += 45;
        reasons.push('Subdomain menyamar sebagai brand: ' + brand);
        break;
      }

      // C. Exact match mainLabel dengan brand tapi di TLD lain yang tidak resmi (misal: paypal.xyz)
      if (mainLabel === brand) {
        if (!SUSPICIOUS_TLDS.has(topLevel) && !SUSPICIOUS_TLDS.has('.' + etld)) {
          // Domain bukan domain resmi dan berpotensi squatting
          score += 40;
          reasons.push('Brand ' + brand + ' terdaftar di eTLD tidak resmi: ' + etldPlusOne);
        } else {
          score += 50;
          reasons.push('Brand ' + brand + ' di TLD mencurigakan: ' + etldPlusOne);
        }
        break;
      }

      // D. Typosquatting / Kemiripan Karakter pada mainLabel
      // Syarat ketat: panjang minimal 4 huruf untuk menghindari false positive singkatan (misal 'go' vs 'ovo')
      var dist = levenshtein(mainLabel, brand);
      var isTyposquat = false;
      if (mainLabel.length >= 6 && dist <= 2 && mainLabel !== brand) {
        isTyposquat = true;
      } else if (mainLabel.length >= 4 && dist === 1 && mainLabel !== brand) {
        isTyposquat = true;
      }

      if (isTyposquat) {
        score += 50;
        reasons.push('Nama domain mirip brand: ' + brand + ' (typosquatting)');
        break;
      }

      // E. Sisipan / Afiks Brand dalam mainLabel (misal: bca-klik, verify-paypal, mybri)
      if (mainLabel.length > brand.length && mainLabel.indexOf(brand) !== -1) {
        // Pastikan bukan substring kebetulan pada kata umum, cek separator atau posisi
        if (mainLabel.startsWith(brand + '-') || mainLabel.endsWith('-' + brand) ||
            mainLabel.startsWith(brand + '_') || mainLabel.endsWith('_' + brand) ||
            mainLabel.indexOf('-' + brand + '-') !== -1) {
          score += 35;
          reasons.push('Brand ' + brand + ' disisipi dengan tanda hubung: ' + mainLabel);
          break;
        }
      }
    }

    // 7. Kedalaman subdomain (hanya dihitung dari subdomains sebelum eTLD+1)
    if (subdomains.length >= 3) {
      score += 15;
      reasons.push('Terlalu banyak subdomain');
    }

    // 8. Panjang Hostname berlebihan
    if (host.length > 50) {
      score += 10;
      reasons.push('Hostname sangat panjang');
    }

    return { score: Math.min(score, 100), reasons: reasons };
  }

  globalThis.FerroShieldPhishing = {
    evaluate: evaluate,
    parseDomain: parseDomain
  };
})();
