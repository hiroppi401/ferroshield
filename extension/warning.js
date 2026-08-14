/* FerroShield Browser Guard - logika halaman peringatan. */
(function () {
  'use strict';

  function params() {
    var out = {};
    var raw = decodeURIComponent(window.location.hash.replace(/^#/, ''));
    raw.split('&').forEach(function (pair) {
      var i = pair.indexOf('=');
      if (i > 0) {
        var k = pair.slice(0, i);
        var v = pair.slice(i + 1);
        if (k) out[k] = v;
      }
    });
    return out;
  }

  var p = params();
  var targetUrl = p.url || '';
  var category = p.category || 'block';
  var match = p.match || '';
  var reason = p.reason || '';

  var label = {
    blacklist: 'Blacklist FerroShield',
    ip: 'IP diblokir FerroShield',
    domain: 'Domain diblokir FerroShield',
    phishing: 'Phishing / scam',
    miner: 'Web miner',
    block: 'Terblokir'
  };
  document.getElementById('category').textContent = label[category] || label.block;
  document.getElementById('url').textContent = targetUrl || match;
  document.getElementById('reason').textContent =
    reason || 'Situs ini diblokir oleh aturan FerroShield.';

  var host = '';
  try { host = new URL(targetUrl || 'https://' + match).hostname; } catch (e) { /* ignore */ }

  document.getElementById('back').addEventListener('click', function () {
    window.history.length > 1 ? window.history.back() : window.close();
  });

  document.getElementById('proceed').addEventListener('click', async function () {
    if (host) {
      try {
        await chrome.storage.session.get({ bypass: {} }).then(function (stored) {
          var bypass = stored.bypass || {};
          bypass[host] = { at: Date.now() };
          return chrome.storage.session.set({ bypass: bypass });
        });
      } catch (e) { /* storage.session tak tersedia */ }
    }
    if (targetUrl) {
      window.location.href = targetUrl;
    } else if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });
})();
