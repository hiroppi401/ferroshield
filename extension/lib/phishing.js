/* FerroShield Browser Guard - heuristik phishing/scam lokal.
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
    'indihome': ['indihome.net']
  };

  var SUSPICIOUS_TLDS = new Set([
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.club', '.online',
    '.site', '.work', '.stream', '.download', '.review', '.bid', '.trade',
    '.men', '.loan', '.zip', '.country', '.click', '.link', '.surf',
    '.rest', '.bar', '.cam', '.live', '.life', '.kim', '.icu', '.gdn',
    '.buzz', '.host', '.space', '.press', '.fun', '.vip', '.win',
    '.wang', '.science', '.party', '.racing', '.faith', '.date',
    '.webcam', '.accountant', '.stream', '.monster', '.skin', '.quest',
    '.loan', '.loan', '.cricket', '.golf', '.jewelry'
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

  var MULTI_SUFFIX = new Set([
    'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au',
    'co.nz', 'co.jp', 'ne.jp', 'com.br', 'com.mx', 'com.ar', 'com.tr',
    'co.id', 'or.id', 'web.id', 'ac.id', 'co.in', 'com.cn', 'co.za',
    'com.sg', 'com.my', 'com.ph', 'com.hk', 'co.kr', 'com.tw', 'co.th',
    'com.vn', 'com.eg', 'com.sa', 'com.ua', 'com.ru', 'co.il', 'com.pk',
    'com.bd', 'co.ke', 'com.ng', 'com.gh'
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

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
      score += 35;
      reasons.push('Host berupa IP literal');
    }
    if (host.indexOf('xn--') === 0 || host.indexOf('.xn--') !== -1) {
      score += 30;
      reasons.push('Punycode / homograph');
    }

    var labels = host.split('.');
    var tld = labels[labels.length - 1];
    var baseLen = 1;
    if (labels.length >= 2 && MULTI_SUFFIX.has(labels[labels.length - 2] + '.' + tld)) {
      baseLen = 2;
    }
    var nameLabels = labels.slice(0, labels.length - baseLen);
    if (nameLabels.length && nameLabels[0] === 'www') {
      nameLabels = nameLabels.slice(1);
    }
    var name = nameLabels.join('.');
    var mainLabel = nameLabels.length ? nameLabels[nameLabels.length - 1] : '';

    if (SUSPICIOUS_TLDS.has('.' + tld)) {
      score += 30;
      reasons.push('TLD mencurigakan: .' + tld);
    }

    var keywordHit = null;
    for (var k = 0; k < SUSPICIOUS_KEYWORDS.length; k++) {
      var kw = SUSPICIOUS_KEYWORDS[k];
      if (host.indexOf(kw) !== -1) { keywordHit = kw; break; }
    }
    if (keywordHit) {
      score += 18;
      reasons.push('Kata kunci mencurigakan: ' + keywordHit);
    }

    for (var b = 0; b < BRANDS.length; b++) {
      var brand = BRANDS[b];
      var official = BRAND_OFFICIAL[brand];
      if (official && official.indexOf(host) !== -1) {
        return { score: 0, reasons: [] };
      }
      // mainLabel persis = brand dan TLD tidak mencurigakan -> domain asli/aman.
      if (mainLabel === brand && !SUSPICIOUS_TLDS.has('.' + tld)) {
        return { score: 0, reasons: [] };
      }
      var signal = 0;
      if (name.indexOf(brand) !== -1) {
        signal = 40;
      } else if (mainLabel && mainLabel !== brand && levenshtein(mainLabel, brand) <= 2) {
        signal = 40;
        reasons.push('Nama domain mirip brand: ' + brand);
      } else if (mainLabel && mainLabel !== brand && mainLabel.length >= brand.length &&
                 (mainLabel.indexOf(brand) === 0 ||
                  mainLabel.indexOf(brand) === mainLabel.length - brand.length)) {
        signal = 35;
        reasons.push('Brand ' + brand + ' disisipi/bertambahan');
      }
      if (signal > 0) {
        score += signal;
        break;
      }
    }

    if (nameLabels.length >= 3) {
      score += 15;
      reasons.push('Terlalu banyak subdomain');
    }
    if (host.length > 45) {
      score += 10;
      reasons.push('Hostname sangat panjang');
    }

    return { score: Math.min(score, 100), reasons: reasons };
  }

  globalThis.FerroShieldPhishing = { evaluate: evaluate };
})();
