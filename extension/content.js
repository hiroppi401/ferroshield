/* FerroShield Browser Guard - deteksi web miner heuristik (dokumen).
 * Ringan: satu MutationObserver untuk elemen <script>. Blokir script yang
 * jelas-jelas miner (coinhive/coin-hive/webmine/coinimp/cryptonight/...).
 * DNR static rules menangani request jaringan; ini lapisan untuk script
 * inline/obfuscated yang belum tertangkap.
 */
(function () {
  'use strict';

  var LIB_PATTERNS = [
    /coinhive/i, /coin-hive/i, /coinimp/i, /cryptoloot/i,
    /webmine/i, /cryptonight/i, /coinerra/i, /crypto-loot/i,
    /hash888/i, /abmr\.net/i
  ];
  var MINING_VERBS = [
    'hashesPerSecond', 'startMining', 'stopMining', 'autoThreads',
    'WebAssembly', 'getMiner', 'throttle', 'mine-', 'miner'
  ];

  function hitsLib(src) {
    return !!src && LIB_PATTERNS.some(function (r) { return r.test(src); });
  }

  function hitsInlineText(text) {
    if (!text) return false;
    var lib = LIB_PATTERNS.some(function (r) { return r.test(text); });
    if (!lib) return false;
    return MINING_VERBS.some(function (v) { return text.indexOf(v) !== -1; });
  }

  function blockEl(el) {
    try { el.remove(); } catch (e) { /* ignore */ }
    try {
      chrome.runtime.sendMessage({ type: 'fs:miner-blocked', n: 1 });
    } catch (e) { /* ignore */ }
  }

  var observer = new MutationObserver(function (mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var nodes = mutations[i].addedNodes;
      for (var j = 0; j < nodes.length; j++) {
        var node = nodes[j];
        if (node.nodeType !== 1) continue;
        var tag = node.tagName ? node.tagName.toUpperCase() : '';
        if (tag === 'SCRIPT') {
          if (hitsLib(node.src) || hitsInlineText(node.textContent)) blockEl(node);
        } else if (node.querySelectorAll) {
          var scripts = node.querySelectorAll('script[src], script:not([src])');
          for (var k = 0; k < scripts.length; k++) {
            var s = scripts[k];
            if (hitsLib(s.src) || hitsInlineText(s.textContent)) blockEl(s);
          }
        }
      }
    }
  });

  if (document.documentElement) {
    observer.observe(document.documentElement, { childList: true, subtree: true });
  } else {
    document.addEventListener('DOMContentLoaded', function () {
      observer.observe(document.documentElement, { childList: true, subtree: true });
    });
  }
})();
