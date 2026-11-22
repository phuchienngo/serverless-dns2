/**
 * @fileoverview The `/apple` page: a script in the browser tries addresses
 * of Cloudflare's network, keeps the ones that answer fastest and with the
 * fewest lost packets from where the visitor is, and offers an Apple DNS
 * profile (`.mobileconfig`) that connects to them. The server cannot measure
 * the visitor's path, so the browser does.
 */

import {getPinnableRanges} from './cloudflare-ips.js';

/** The page's script. No backticks or template placeholders: it sits in a template. */
export const PAGE_SCRIPT = `
(function () {
  var host = location.hostname;
  var TIMEOUT = 2500;
  var PER_RANGE = 10;
  var SHORTLIST = 12;
  var EXTRA_PROBES = 4;
  var $ = function (id) { return document.getElementById(id); };

  // Time to a failed TLS handshake (the certificate is not for an address),
  // or null if nothing came back in time.
  function probe(ip) {
    return new Promise(function (resolve) {
      var controller = new AbortController();
      var lost = false;
      var timer = setTimeout(function () { lost = true; controller.abort(); }, TIMEOUT);
      var started = performance.now();
      fetch('https://' + ip + '/cdn-cgi/trace', {
        mode: 'no-cors', cache: 'no-store', signal: controller.signal
      }).then(
        function () { return performance.now() - started; },
        function () { return lost ? null : performance.now() - started; }
      ).then(function (ms) { clearTimeout(timer); resolve(ms); });
    });
  }

  function pool(items, size, work) {
    var next = 0;
    function worker() {
      if (next >= items.length) { return Promise.resolve(); }
      var item = items[next++];
      return work(item).then(worker);
    }
    var workers = [];
    for (var i = 0; i < size; i++) { workers.push(worker()); }
    return Promise.all(workers);
  }

  function addresses(cidr, count) {
    var parts = cidr.split('/');
    var o = parts[0].split('.').map(Number);
    var base = ((o[0] * 256 + o[1]) * 256 + o[2]) * 256 + o[3];
    var size = Math.pow(2, 32 - Number(parts[1]));
    var out = [];
    for (var i = 0; i < count; i++) {
      var n = base + 1 + Math.floor(Math.random() * (size - 2));
      out.push([n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.'));
    }
    return out;
  }

  function median(values) {
    var sorted = values.slice().sort(function (a, b) { return a - b; });
    return sorted.length ? sorted[Math.floor(sorted.length / 2)] : Infinity;
  }

  var results = [];

  function show() {
    var body = $('rows');
    body.textContent = '';
    results.forEach(function (r, i) {
      var tr = document.createElement('tr');
      var box = document.createElement('input');
      box.type = 'checkbox';
      box.checked = i < 2;
      box.dataset.ip = r.ip;
      var cells = [box, r.ip, Math.round(r.ms) + ' ms', Math.round(r.loss * 100) + '%'];
      cells.forEach(function (cell) {
        var td = document.createElement('td');
        if (typeof cell === 'string') { td.textContent = cell; } else { td.appendChild(cell); }
        tr.appendChild(td);
      });
      body.appendChild(tr);
    });
    $('results').hidden = false;
  }

  function measure() {
    $('start').disabled = true;
    $('status').textContent = 'Loading the address list...';
    fetch('/cloudflare-ips.json').then(function (r) { return r.json(); }).then(function (list) {
      var candidates = [];
      list.v4.forEach(function (cidr) {
        candidates = candidates.concat(addresses(cidr, PER_RANGE));
      });
      var done = 0;
      var alive = [];
      $('status').textContent = 'Trying ' + candidates.length + ' addresses...';
      return pool(candidates, 8, function (ip) {
        return probe(ip).then(function (ms) {
          done++;
          $('status').textContent = 'First pass: ' + done + '/' + candidates.length;
          if (ms !== null) { alive.push({ip: ip, times: [ms], lost: 0, total: 1}); }
        });
      }).then(function () {
        alive.sort(function (a, b) { return a.times[0] - b.times[0]; });
        var shortlist = alive.slice(0, SHORTLIST);
        var step = 0;
        var all = shortlist.length * EXTRA_PROBES;
        return pool(shortlist, 4, function (entry) {
          var chain = Promise.resolve();
          for (var i = 0; i < EXTRA_PROBES; i++) {
            chain = chain.then(function () { return probe(entry.ip); }).then(function (ms) {
              entry.total++;
              if (ms === null) { entry.lost++; } else { entry.times.push(ms); }
              step++;
              $('status').textContent = 'Second pass: ' + step + '/' + all;
            });
          }
          return chain;
        }).then(function () { return shortlist; });
      });
    }).then(function (shortlist) {
      results = shortlist.map(function (e) {
        return {ip: e.ip, ms: median(e.times), loss: e.lost / e.total};
      }).sort(function (a, b) { return (a.loss - b.loss) || (a.ms - b.ms); });
      $('status').textContent = results.length
        ? 'Done. The best are ticked.'
        : 'No address answered: check your connection.';
      show();
      $('start').disabled = false;
    }).catch(function (error) {
      $('status').textContent = 'Failed: ' + error;
      $('start').disabled = false;
    });
  }

  function uuid() { return crypto.randomUUID().toUpperCase(); }

  function profile(ips) {
    var id = host.split('.').reverse().join('.') + '.dns';
    var servers = ips.length
      ? '<key>ServerAddresses</key><array>' +
        ips.map(function (ip) { return '<string>' + ip + '</string>'; }).join('') +
        '</array>'
      : '';
    return '<?xml version="1.0" encoding="UTF-8"?>\\n' +
      '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\\n' +
      '<plist version="1.0"><dict>' +
      '<key>PayloadDisplayName</key><string>' + host + '</string>' +
      '<key>PayloadDescription</key><string>Encrypted DNS over HTTPS on all networks.</string>' +
      '<key>PayloadIdentifier</key><string>' + id + '.profile</string>' +
      '<key>PayloadScope</key><string>System</string>' +
      '<key>PayloadType</key><string>Configuration</string>' +
      '<key>PayloadUUID</key><string>' + uuid() + '</string>' +
      '<key>PayloadVersion</key><integer>1</integer>' +
      '<key>PayloadContent</key><array><dict>' +
      '<key>DNSSettings</key><dict>' +
      '<key>DNSProtocol</key><string>HTTPS</string>' +
      '<key>ServerURL</key><string>https://' + host + '/dns-query</string>' +
      servers + '</dict>' +
      '<key>OnDemandRules</key><array>' +
      '<dict><key>Action</key><string>EvaluateConnection</string>' +
      '<key>ActionParameters</key><array><dict>' +
      '<key>DomainAction</key><string>NeverConnect</string>' +
      '<key>Domains</key><array><string>captive.apple.com</string></array>' +
      '</dict></array></dict>' +
      '<dict><key>Action</key><string>Connect</string></dict></array>' +
      '<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>' +
      '<key>PayloadIdentifier</key><string>' + id + '.profile.dnsSettings.managed</string>' +
      '<key>PayloadUUID</key><string>' + uuid() + '</string>' +
      '<key>PayloadDisplayName</key><string>' + host + '</string>' +
      '<key>PayloadOrganization</key><string>' + host + '</string>' +
      '<key>PayloadVersion</key><integer>1</integer>' +
      '</dict></array></dict></plist>\\n';
  }

  function save(ips) {
    var blob = new Blob([profile(ips)], {type: 'application/x-apple-aspen-config'});
    var link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = host + '.mobileconfig';
    link.click();
  }

  function download() {
    var ips = Array.prototype.slice.call(document.querySelectorAll('input[data-ip]'))
      .filter(function (box) { return box.checked; })
      .map(function (box) { return box.dataset.ip; });
    if (!ips.length) { $('status').textContent = 'Tick at least one address.'; return; }
    save(ips);
  }

  $('host').textContent = host;
  $('start').onclick = measure;
  $('download').onclick = download;
  $('plain').onclick = function () { save([]); };
})();
`;

const PAGE = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>DNS profile</title>
<style>
  body { font: 16px/1.5 system-ui, sans-serif; max-width: 36rem; margin: 2rem auto; padding: 0 1rem; }
  table { border-collapse: collapse; width: 100%; margin: 1rem 0; }
  td, th { text-align: left; padding: .25rem .5rem; border-bottom: 1px solid #8884; }
  button { font: inherit; padding: .4rem .9rem; }
  #status { color: #666; min-height: 1.5em; }
</style>
</head>
<body>
<h1>Apple DNS profile</h1>
<p>A DNS profile for <b id="host"></b>.</p>
<h2>Normal network</h2>
<p><button id="plain">Download profile</button></p>
<p>The profile connects the usual way, with no address pinned.</p>
<h2>Weak network</h2>
<p>Finds the Cloudflare addresses that work best from where you are, then makes a
profile that connects to them.</p>
<p><button id="start">Measure</button></p>
<p id="status"></p>
<div id="results" hidden>
<table><thead><tr><th></th><th>Address</th><th>Median</th><th>Lost</th></tr></thead>
<tbody id="rows"></tbody></table>
<p><button id="download">Download profile with these addresses</button></p>
</div>
<p>Open the downloaded file, then install it in System Settings, Privacy &amp; Security, Profiles.</p>
<script>${PAGE_SCRIPT}</script>
</body>
</html>
`;

/** The `/apple` page. */
export function profileResponse(): Response {
  return new Response(PAGE, {
    headers: {'content-type': 'text/html; charset=utf-8'},
  });
}

/**
 * The ranges the page may pick addresses from: those that answered for this
 * domain when the build tried them.
 */
export function rangesResponse(): Response {
  const v4 = getPinnableRanges();
  return new Response(JSON.stringify({v4}), {
    headers: {
      'content-type': 'application/json',
      'cache-control': 'public, max-age=3600',
    },
  });
}
