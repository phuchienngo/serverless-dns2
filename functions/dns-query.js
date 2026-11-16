// Minimal DoH gateway for Cloudflare Pages.
//  - forwards to env.UPSTREAM (blocklist lives there)
//  - injects ECS from the client's real IP (/24 v4, /48 v6)
//  - custom CDN redirects (source -> target) for A/AAAA
//  - DDR: answers SVCB for _dns.resolver.arpa and _dns.<this host>

const ECS_ENABLED = true;
const MAX_QUERY = 512;
const UPSTREAM_TIMEOUT_MS = 4000;

// "source": "target" -> source resolves to target's A/AAAA answers
const REDIRECTS = {
  "www.bilibili.tv": "www.bilibili.tv.w.cdngslb.com",
};

const enc = new TextEncoder();
const dec = new TextDecoder();

// ---------- DNS helpers ----------
const u16 = (n) => [n >> 8, n & 255];

function encName(name) {
  const out = [];
  for (const l of name.replace(/\.$/, "").split(".").filter(Boolean)) {
    const b = enc.encode(l);
    out.push(b.length, ...b);
  }
  out.push(0);
  return out;
}

function parseQuestion(buf) {
  if (buf.length < 17 || buf.length > MAX_QUERY) throw new Error("bad length");
  const v = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  if (buf[2] & 0x80 || v.getUint16(4) !== 1) throw new Error("not a query");
  let o = 12;
  const labels = [];
  for (;;) {
    const l = buf[o];
    if (l === undefined || l & 0xc0 || o + 1 + l >= buf.length) throw new Error("bad name");
    if (l === 0) break;
    labels.push(dec.decode(buf.subarray(o + 1, o + 1 + l)));
    o += l + 1;
  }
  o++;
  if (o + 4 > buf.length) throw new Error("truncated");
  return {
    id: v.getUint16(0),
    name: labels.join(".").toLowerCase(),
    type: v.getUint16(o),
    raw: Array.from(buf.subarray(12, o + 4)), // original question bytes (keeps 0x20 case)
  };
}

function ipToEcs(ip) {
  let family, bytes;
  if (ip.includes(":")) {
    family = 2;
    const [h, t = ""] = ip.split("::");
    const head = h ? h.split(":") : [], tail = t ? t.split(":") : [];
    const g = ip.includes("::") ? [...head, ...Array(8 - head.length - tail.length).fill("0"), ...tail] : head;
    bytes = g.slice(0, 3).flatMap((x) => u16(parseInt(x || "0", 16) || 0));
  } else {
    family = 1;
    bytes = ip.split(".").slice(0, 3).map((x) => Number(x) & 255);
  }
  const data = [0, family, family === 1 ? 24 : 48, 0, ...bytes];
  return [0, 8, 0, data.length, ...data]; // EDNS option code 8
}

function buildQuery(question, ecs) {
  const opt = [0, 0, 41, 16, 0, 0, 0, 0, 0, 0, ecs ? ecs.length : 0, ...(ecs || [])];
  return new Uint8Array([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, ...question, ...opt]);
}

async function forward(env, wire) {
  const r = await fetch(env.UPSTREAM, {
    method: "POST",
    headers: { "content-type": "application/dns-message", accept: "application/dns-message" },
    body: wire,
    signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
  });
  if (!r.ok) throw new Error(`upstream ${r.status}`);
  const b = new Uint8Array(await r.arrayBuffer());
  if (b.length < 12) throw new Error("short upstream response");
  return b;
}

function skipName(b, o) {
  for (;;) {
    if (o >= b.length) throw new Error("bad response");
    const l = b[o];
    if (l === 0) return o + 1;
    if ((l & 0xc0) === 0xc0) return o + 2;
    o += l + 1;
  }
}

// walk the answer section: [{start, type, ttl, len, dataStart}]
function answers(resp) {
  const v = new DataView(resp.buffer, resp.byteOffset, resp.byteLength);
  let o = skipName(resp, 12) + 4;
  const out = [];
  for (let i = 0, n = v.getUint16(6); i < n; i++) {
    const start = o;
    o = skipName(resp, o);
    if (o + 10 > resp.length) throw new Error("bad response");
    const len = v.getUint16(o + 8);
    if (o + 10 + len > resp.length) throw new Error("bad response");
    out.push({ start: o, type: v.getUint16(o), ttl: v.getUint32(o + 4), len });
    o += 10 + len;
  }
  return out;
}

function minTtl(resp) {
  try {
    const a = answers(resp);
    return a.length ? Math.min(...a.map((x) => x.ttl), 3600) : 30;
  } catch { return 30; }
}

// ---------- special answers ----------
function respond(q, rcode, rrs) {
  // header: id, flags, qd=1, an, ns=0, ar=0 ; then question ; then answers
  return new Uint8Array([...u16(q.id), 0x81, 0x80 | rcode, 0, 1, ...u16(rrs.length), 0, 0, 0, 0, ...q.raw, ...rrs.flat()]);
}

// keep only A/AAAA, owner pointing at the original question
function redirected(resp, q) {
  const rcode = resp[3] & 15;
  const rrs = answers(resp)
    .filter((a) => a.type === 1 || a.type === 28)
    .map((a) => [0xc0, 12, ...resp.subarray(a.start, a.start + 10 + a.len)]);
  return { body: respond(q, rcode, rrs), ttl: minTtl(resp) };
}

function ddrAnswer(q, host) {
  const alpn = [0, 1, 0, 6, 2, 104, 50, 2, 104, 51]; // h2,h3
  const path = enc.encode("/dns-query{?dns}");
  const rdata = [0, 1, ...encName(host), ...alpn, 0, 7, ...u16(path.length), ...path];
  return respond(q, 0, [[0xc0, 12, 0, 64, 0, 1, 0, 0, 1, 44, ...u16(rdata.length), ...rdata]]);
}

// ---------- handler ----------
export async function onRequest({ request, env, waitUntil }) {
  const url = new URL(request.url);
  if (!env.UPSTREAM) return new Response("UPSTREAM not configured", { status: 500 });

  let wire;
  try {
    if (request.method === "POST") {
      if (Number(request.headers.get("content-length")) > MAX_QUERY) return new Response("too large", { status: 413 });
      wire = new Uint8Array(await request.arrayBuffer());
    } else if (request.method === "GET" && url.searchParams.get("dns")) {
      const s = url.searchParams.get("dns");
      if (s.length > MAX_QUERY * 2) return new Response("too large", { status: 413 });
      wire = Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
    } else {
      return new Response("method not allowed", { status: 405, headers: { allow: "GET, POST" } });
    }
  } catch { return new Response("bad request", { status: 400 }); }

  let q;
  try { q = parseQuestion(wire); } catch { return new Response("bad dns message", { status: 400 }); }

  const reply = (b, ttl = 30) =>
    new Response(b, { headers: { "content-type": "application/dns-message", "cache-control": `private, max-age=${ttl}` } });

  try {
    // DDR
    if (q.type === 64 && (q.name === "_dns.resolver.arpa" || q.name === `_dns.${url.hostname}`))
      return reply(ddrAnswer(q, url.hostname), 300);

    const ip = request.headers.get("CF-Connecting-IP");
    const ecs = ECS_ENABLED && ip ? ipToEcs(ip) : null;

    const target = REDIRECTS[q.name];
    // HTTPS/SVCB hints would leak the original IPs -> answer NODATA for them
    if (target && (q.type === 64 || q.type === 65)) return reply(respond(q, 0, []), 60);

    // cache (per data center): key = name + type + client ECS prefix
    const cache = caches.default;
    const key = new Request(`${url.origin}/__cache/${encodeURIComponent(q.name)}/${q.type}/${ecs ? ecs.slice(4).join("-") : "none"}`);
    const hit = await cache.match(key);
    if (hit) {
      const b = new Uint8Array(await hit.arrayBuffer());
      const age = Math.floor(Date.now() / 1000) - Number(hit.headers.get("x-t"));
      b.set(u16(q.id), 0);
      b.set(q.raw, 12); // same length as cached question, restores client's 0x20 case
      const v = new DataView(b.buffer);
      let left = 30;
      const a = answers(b);
      if (a.length) left = Math.max(Math.min(...a.map((x) => x.ttl)) - age, 1);
      for (const x of a) v.setUint32(x.start + 4, Math.max(x.ttl - age, 1));
      const r = reply(b, left);
      r.headers.set("x-cache", "HIT");
      return r;
    }

    let body, ttl;
    if (target && (q.type === 1 || q.type === 28)) {
      const resp = await forward(env, buildQuery([...encName(target), ...u16(q.type), 0, 1], ecs));
      ({ body, ttl } = redirected(resp, q));
    } else {
      body = await forward(env, buildQuery(q.raw, ecs));
      body[0] = q.id >> 8; body[1] = q.id & 255;
      ttl = minTtl(body);
    }
    if ([0, 3].includes(body[3] & 15) && !(body[2] & 2))
      waitUntil(cache.put(key, new Response(body, { headers: { "cache-control": `public, max-age=${ttl}`, "x-t": String(Math.floor(Date.now() / 1000)) } })));
    return reply(body, ttl);
  } catch {
    return reply(respond(q, 2, []), 5); // SERVFAIL
  }
}
