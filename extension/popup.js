/* FerroShield Browser Guard - logika popup. */
(function () {
  'use strict';

  var els = {};

  function $(id) { return document.getElementById(id); }

  function bindToggle(id, key, onChange) {
    var el = $(id);
    el.addEventListener('change', function () {
      chrome.runtime.sendMessage({ type: 'fs:setSetting', key: key, value: el.checked });
      if (onChange) onChange(el.checked);
    });
  }

  function render(state) {
    var s = state.settings || {};
    var c = state.counters || {};
    els.enabled.checked = !!s.enabled;
    els.daemon.checked = !!s.daemon;
    els.phishing.checked = !!s.phishing;
    els.miner.checked = !!s.miner;

    var on = !!s.enabled;
    document.querySelectorAll('.switch input').forEach(function (input) {
      input.disabled = !on && input.id !== 'enabled';
    });

    var dot = $('statusDot');
    if (state.connected) {
      dot.className = 'dot on';
      $('statusText').textContent = 'Daemon terhubung';
    } else {
      dot.className = 'dot';
      $('statusText').textContent = 'Daemon tidak terhubung';
    }

    $('nBlacklist').textContent = c.blacklist || 0;
    $('nPhishing').textContent = c.phishing || 0;
    $('nMiner').textContent = c.miner || 0;
    var synced = c.synced || 0;
    $('syncedInfo').textContent = synced > 0
      ? synced + ' domain blacklist tersinkron di browser'
      : 'Belum ada domain blacklist tersinkron';
  }

  document.addEventListener('DOMContentLoaded', function () {
    els.enabled = $('enabled');
    els.daemon = $('daemon');
    els.phishing = $('phishing');
    els.miner = $('miner');

    bindToggle('enabled', 'enabled', function (v) { if (!v) render({ settings: { enabled: false }, connected: true }); });
    bindToggle('daemon', 'daemon');
    bindToggle('phishing', 'phishing');
    bindToggle('miner', 'miner');

    $('resync').addEventListener('click', function () {
      $('resync').textContent = 'Menyinkronkan...';
      chrome.runtime.sendMessage({ type: 'fs:resync' }, function (res) {
        $('resync').textContent = 'Sinkronkan';
        if (res && res.ok) {
          chrome.runtime.sendMessage({ type: 'fs:getState' }, function (st) { render(st); });
        }
      });
    });

    $('dashboard').addEventListener('click', function (e) {
      e.preventDefault();
      chrome.tabs.create({ url: 'http://127.0.0.1:8686/' });
    });

    chrome.runtime.sendMessage({ type: 'fs:getState' }, function (state) {
      if (chrome.runtime.lastError) return;
      render(state);
    });
  });
})();
