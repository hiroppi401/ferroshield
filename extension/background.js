/* FerroShield Browser Guard - background worker (Manifest V3).
 * Berjalan sebagai service worker di Chrome, dan background event page di
 * Firefox (manifest mendeklarasikan keduanya). `importScripts` hanya ada di
 * worker; di Firefox phishing.js dimuat lewat array `background.scripts`.
 * 1) Bootstrap token dashboard dari halaman daemon (meta tag).
 * 2) Cek setiap navigasi utama ke /api/url/check + heuristik phishing.
 * 3) Sinkronkan blacklist domain daemon ke declarativeNetRequest dynamic rules.
 */
if (typeof importScripts === 'function') {
  importScripts('lib/phishing.js');
}

var DAEMON_ORIGIN = 'http://127.0.0.1:8686';
var MAX_DNR_RULES = 5000;
var NAV_CACHE_TTL = 30 * 1000;
var BYPASS_TTL = 30 * 60 * 1000;

// Resource types yang didukung kedua browser (Chrome & Firefox DNR).
var ALL_RESOURCE_TYPES = ['main_frame', 'sub_frame', 'stylesheet', 'script',
  'image', 'font', 'object', 'xmlhttprequest', 'ping', 'media', 'websocket',
  'other'];

var DEFAULTS = { enabled: true, daemon: true, phishing: true, miner: true };

var state = {
  token: null,
  settings: Object.assign({}, DEFAULTS),
  counters: { blacklist: 0, phishing: 0, miner: 0, synced: 0 },
  navCache: new Map()
};

function getStorage(keys) { return chrome.storage.local.get(keys); }
function setStorage(obj) { return chrome.storage.local.set(obj); }
function getSession(keys) { return chrome.storage.session.get(keys); }
function setSession(obj) { return chrome.storage.session.set(obj); }

async function loadState() {
  var stored = await getStorage(['settings', 'counters']);
  state.settings = Object.assign({}, DEFAULTS, stored.settings || {});
  state.counters = Object.assign(
    { blacklist: 0, phishing: 0, miner: 0, synced: 0 },
    stored.counters || {}
  );
}

function saveState() {
  return setStorage({ settings: state.settings, counters: state.counters });
}

async function bootstrapToken() {
  state.token = null;
  try {
    var res = await fetch(DAEMON_ORIGIN + '/', { cache: 'no-store' });
    if (!res.ok) return false;
    var html = await res.text();
    var m = html.match(/name="ferroshield-token" content="([0-9a-f]{64})"/i);
    if (m) { state.token = m[1]; return true; }
  } catch (e) { /* daemon offline */ }
  return false;
}

async function ensureToken() {
  if (state.token) return true;
  return bootstrapToken();
}

async function daemonRequest(path) {
  if (!(await ensureToken())) return null;
  try {
    var res = await fetch(DAEMON_ORIGIN + path, {
      headers: { Authorization: 'Bearer ' + state.token },
      cache: 'no-store'
    });
    if (res.status === 401) { state.token = null; return null; }
    if (!res.ok) return null;
    return res.json();
  } catch (e) {
    return null;
  }
}

async function checkUrl(fullUrl) {
  var data = await daemonRequest('/api/url/check?url=' + encodeURIComponent(fullUrl));
  return data || { blocked: false, daemon: false };
}

async function syncDynamicRules() {
  var existing = await chrome.declarativeNetRequest.getDynamicRules();
  var removeRuleIds = existing.map(function (r) { return r.id; });
  var addRules = [];
  if (state.settings.enabled && state.settings.daemon) {
    var data = await daemonRequest('/api/blacklist/domains');
    if (data && Array.isArray(data.domains)) {
      var seen = {};
      var domains = [];
      for (var i = 0; i < data.domains.length; i++) {
        var d = String(data.domains[i]).trim().toLowerCase();
        if (!d || d.indexOf('.') === -1 || d.indexOf(' ') !== -1 || seen[d]) continue;
        seen[d] = true;
        domains.push(d);
      }
      var take = domains.slice(0, MAX_DNR_RULES);
      addRules = take.map(function (d, i) {
        return {
          id: 1000 + i,
          priority: 2,
          action: { type: 'block' },
          condition: {
            urlFilter: '||' + d,
            isUrlFilterCaseSensitive: false,
            resourceTypes: ALL_RESOURCE_TYPES
          }
        };
      });
    }
  }
  await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: removeRuleIds, addRules: addRules });
  state.counters.synced = addRules.length;
  await saveState();
  return addRules.length;
}

function isUsableUrl(url) {
  return /^https?:/i.test(url) &&
    url.indexOf(DAEMON_ORIGIN) !== 0 &&
    url.indexOf(chrome.runtime.getURL('')) !== 0;
}

async function isBypassed(host) {
  var stored = await getSession({ bypass: {} });
  var entry = (stored.bypass || {})[host];
  return !!(entry && Date.now() - entry.at < BYPASS_TTL);
}

async function addBypass(host) {
  var stored = await getSession({ bypass: {} });
  var bypass = stored.bypass || {};
  bypass[host] = { at: Date.now() };
  await setSession({ bypass: bypass });
}

function increment(key, n) {
  state.counters[key] = (state.counters[key] || 0) + (n || 1);
  saveState();
}

function redirectToWarning(tabId, url, category, matched, reason) {
  var params = [
    'url=' + encodeURIComponent(url),
    'category=' + encodeURIComponent(category || 'block'),
    'match=' + encodeURIComponent(matched || ''),
    'reason=' + encodeURIComponent(reason || '')
  ].join('&');
  var target = chrome.runtime.getURL('warning.html') + '#' + params;
  chrome.tabs.update(tabId, { url: target });
}

chrome.webNavigation.onCommitted.addListener(async function (details) {
  if (details.frameId !== 0) return;
  var url = details.url;
  if (!isUsableUrl(url)) return;
  if (!state.settings.enabled) return;

  var host;
  try { host = new URL(url).hostname.toLowerCase(); } catch (e) { return; }
  if (!host || await isBypassed(host)) return;

  var now = Date.now();
  var cached = state.navCache.get(host);
  if (cached && now - cached.at < NAV_CACHE_TTL) {
    if (cached.blocked) {
      increment(cached.category);
      redirectToWarning(details.tabId, url, cached.category, cached.match, cached.reason);
    }
    return;
  }

  var verdict = { blocked: false };
  if (state.settings.daemon) {
    try { verdict = await checkUrl(url); } catch (e) { /* daemon offline */ }
  }

  if (verdict.blocked) {
    state.navCache.set(host, { at: now, blocked: true, category: 'blacklist', match: verdict.matched, reason: verdict.reason });
    increment('blacklist');
    redirectToWarning(details.tabId, url, 'blacklist', verdict.matched, verdict.reason);
    return;
  }

  if (state.settings.phishing) {
    var ph = FerroShieldPhishing.evaluate(url);
    if (ph.score >= 50) {
      state.navCache.set(host, { at: now, blocked: true, category: 'phishing', match: host, reason: ph.reasons.join(', ') });
      increment('phishing');
      redirectToWarning(details.tabId, url, 'phishing', host, ph.reasons.join(', '));
      return;
    }
  }

  state.navCache.set(host, { at: now, blocked: false });
}, { url: [{ schemes: ['http', 'https'] }] });

chrome.runtime.onMessage.addListener(function (msg, sender, sendResponse) {
  if (!msg || !msg.type) return;

  if (msg.type === 'fs:miner-blocked') {
    increment('miner', msg.n || 1);
    return;
  }

  if (msg.type === 'fs:getState') {
    sendResponse({ settings: state.settings, counters: state.counters, connected: !!state.token });
    return true;
  }

  if (msg.type === 'fs:setSetting') {
    if (msg.key in state.settings) {
      state.settings[msg.key] = !!msg.value;
      saveState();
      if (msg.key === 'daemon' || msg.key === 'enabled') {
        syncDynamicRules();
      }
      sendResponse({ ok: true });
    } else {
      sendResponse({ ok: false });
    }
    return true;
  }

  if (msg.type === 'fs:resync') {
    syncDynamicRules().then(function (n) { sendResponse({ ok: true, n: n }); });
    return true;
  }

  if (msg.type === 'fs:clearCounters') {
    state.counters = { blacklist: 0, phishing: 0, miner: 0, synced: state.counters.synced || 0 };
    saveState();
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === 'fs:reconnect') {
    bootstrapToken().then(function (ok) { sendResponse({ ok: ok }); });
    return true;
  }
});

chrome.alarms.create('fs-resync', { periodInMinutes: 15 });
chrome.alarms.onAlarm.addListener(function (alarm) {
  if (alarm.name === 'fs-resync') {
    bootstrapToken();
    syncDynamicRules();
  }
});

async function init() {
  await loadState();
  await bootstrapToken();
  await syncDynamicRules();
}

chrome.runtime.onInstalled.addListener(init);
chrome.runtime.onStartup.addListener(init);
init();
