// Shadow on-TV service core. Written for old Node (webOS 4+): no fetch, no object spread.
const http = require('http'), https = require('https'), os = require('os'), fs = require('fs'), crypto = require('crypto'), URL = require('url').URL;

function hfetch(u, o, n) {
  o = o || {}; n = n || 0;
  return new Promise(function (ok, no) {
    const x = new URL(u), m = x.protocol === 'https:' ? https : http;
    const r = m.request({ hostname: x.hostname, port: x.port || undefined, path: x.pathname + x.search, method: o.method || 'GET', headers: o.headers || {}, rejectUnauthorized: false }, function (res) {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && n < 5) { res.resume(); return ok(hfetch(new URL(res.headers.location, u).href, o, n + 1)); }
      const ch = []; res.on('data', function (c) { ch.push(c); });
      res.on('end', function () { const b = Buffer.concat(ch); ok({ status: res.statusCode, headers: res.headers, buf: b, text: function () { return b.toString('utf8'); } }); });
    });
    r.on('error', no); r.setTimeout(25000, function () { r.destroy(new Error('timeout')); }); r.end();
  });
}
const PASS = process.env.SHADOW_PASS || '';
const TOK = crypto.createHash('sha256').update(PASS + '|shadow').digest('hex');
const authed = req => !PASS || (req.headers.cookie || '').split(/;\s*/).indexOf('shadow=' + TOK) >= 0;
function pipeStream(req, res, target, n) {
  n = n || 0; const x = new URL(target), m = x.protocol === 'https:' ? https : http, h = { 'User-Agent': 'Mozilla/5.0' };
  if (req.headers.range) h.Range = req.headers.range;
  const r = m.request({ hostname: x.hostname, port: x.port || undefined, path: x.pathname + x.search, method: 'GET', headers: h, rejectUnauthorized: false }, function (up) {
    if (up.statusCode >= 300 && up.statusCode < 400 && up.headers.location && n < 5) { up.resume(); return pipeStream(req, res, new URL(up.headers.location, target).href, n + 1); }
    const o = { 'Access-Control-Allow-Origin': '*' };
    ['content-type', 'content-length', 'content-range', 'accept-ranges'].forEach(function (k) { if (up.headers[k]) o[k] = up.headers[k]; });
    res.writeHead(up.statusCode, o); up.pipe(res);
  });
  r.on('error', function (e) { if (!res.headersSent) send(res, 502, { error: e.message }); else res.end(); });
  req.on('close', function () { r.destroy(); }); r.end();
}
const cors = { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': '*', 'Access-Control-Allow-Methods': 'GET,POST,OPTIONS' };
function send(res, c, b, t) {
  res.writeHead(c, Object.assign({}, cors, { 'Content-Type': t || 'application/json' }));
  res.end(Buffer.isBuffer(b) || typeof b === 'string' ? b : JSON.stringify(b));
}
const body = req => new Promise(r => { let d = ''; req.on('data', c => d += c); req.on('end', () => { try { r(JSON.parse(d)); } catch (e) { r({}); } }); });
function ip() {
  const all = os.networkInterfaces(); let best = '';
  Object.keys(all).forEach(k => all[k].forEach(i => { if (i.family === 'IPv4' && !i.internal && !best) best = i.address; }));
  return best;
}

// ---------- Stalker ----------
const UA = 'Mozilla/5.0 (QtEmbedded; U; Linux; C) AppleWebKit/533.3 (KHTML, like Gecko) MAG200 stbapp ver: 2 rev: 250 Safari/533.3';
function hdr(mac, tok) {
  const h = { 'User-Agent': UA, 'X-User-Agent': 'Model: MAG250; Link: WiFi', Cookie: 'mac=' + mac + '; stb_lang=en; timezone=GMT' };
  if (tok) h.Authorization = 'Bearer ' + tok; return h;
}
const sess = {};
async function api(s, q) {
  const r = await hfetch(s.api + '?' + new URLSearchParams(Object.assign({}, q, { JsHttpRequest: '1-xml' })).toString(), { headers: hdr(s.mac, s.tok) });
  try { return JSON.parse(r.text()).js; } catch (e) { throw new Error('Unexpected portal response'); }
}
async function session(portal, mac) {
  const k = portal + '|' + mac; if (sess[k]) return sess[k];
  const base = portal.replace(/\/c\/?$/, '').replace(/\/$/, '');
  const cands = /(load|portal)\.php$/.test(portal) ? [portal] : [base + '/server/load.php', base + '/portal.php', base + '/stalker_portal/server/load.php'];
  for (const a0 of cands) {
    try {
      const s = { api: a0, mac: mac }, h = await api(s, { type: 'stb', action: 'handshake', token: '' });
      if (h && h.token) { s.tok = h.token; try { await api(s, { type: 'stb', action: 'get_profile', hd: 1, stb_type: 'MAG250' }); } catch (e) {} return (sess[k] = s); }
    } catch (e) {}
  }
  throw new Error('Portal handshake failed (check portal URL and MAC)');
}
async function withSession(portal, mac, fn) {
  try { return await fn(await session(portal, mac)); } catch (e) { delete sess[portal + '|' + mac]; return await fn(await session(portal, mac)); }
}
const channels = b => withSession(b.portal, b.mac, async s => {
  const g = await api(s, { type: 'itv', action: 'get_genres' }), gm = {};
  (Array.isArray(g) ? g : []).forEach(x => gm[x.id] = x.title);
  const c = await api(s, { type: 'itv', action: 'get_all_channels' });
  return { channels: (c.data || []).map(x => ({ id: x.id, name: x.name, logo: x.logo && /^https?:/.test(x.logo) ? x.logo : '', cmd: x.cmd, cat: gm[x.tv_genre_id] || 'Other' })) };
});
const link = b => withSession(b.portal, b.mac, async s => {
  const j = await api(s, { type: 'itv', action: 'create_link', cmd: b.cmd, series: '', forced_storage: '', disable_ad: 0, download: 0 });
  return { url: String(j.cmd || '').replace(/^ffmpeg\s+/, '').trim() };
});

// ---------- Phone pairing page ----------
const PAGE = '<!doctype html><meta name=viewport content="width=device-width,initial-scale=1"><body style="font-family:sans-serif;background:#0a0f1f;color:#fff;padding:20px;max-width:480px;margin:auto">' +
'<h2>Add subscription to your TV</h2><style>input,select,button{width:100%;padding:14px;margin:6px 0;font-size:16px;border-radius:10px;border:0;box-sizing:border-box}button{background:#4da3ff;color:#fff}</style>' +
'<select id=t onchange=u()><option value=xtream>Xtream Codes</option><option value=m3u>M3U link</option><option value=stalker>Stalker / MAC</option></select>' +
'<input id=n placeholder=Name><input id=h><input id=a><input id=p type=password placeholder=Password><button onclick=go()>Send to TV</button><p id=m></p>' +
'<script>var c=new URLSearchParams(location.search).get("c");function u(){var t=document.getElementById("t").value;h.placeholder=t=="m3u"?"M3U URL":t=="stalker"?"Portal URL":"Server URL (http://host:port)";a.style.display=t=="m3u"?"none":"";a.placeholder=t=="stalker"?"MAC 00:1A:79:..":"Username";p.style.display=t=="xtream"?"":"none"}u();' +
'async function go(){var t=document.getElementById("t").value,N=n.value||"My IPTV";var acc=t=="xtream"?{name:N,type:t,host:h.value,user:a.value,pass:p.value}:t=="m3u"?{name:N,type:t,url:h.value}:{name:N,type:t,portal:h.value,mac:a.value};' +
'var r=await fetch("/pair/submit",{method:"POST",body:JSON.stringify({code:c,acc:acc})});m.textContent=r.ok?"Sent! Check your TV.":"Code expired. Re-open the QR on the TV."}</script>';

const pairs = {};
function start(port, indexPath) {
  const srv = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x'), p = u.pathname;
    if (req.method === 'OPTIONS') return send(res, 204, '');
    if (p === '/ping') return send(res, 200, { auth: authed(req) });
    if (p === '/login') {
      const b = await body(req);
      if (PASS && b.pass === PASS) { res.writeHead(200, Object.assign({}, cors, { 'Content-Type': 'application/json', 'Set-Cookie': 'shadow=' + TOK + '; Path=/; Max-Age=31536000; SameSite=Lax; HttpOnly' + (req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '') })); return res.end('{"ok":1}'); }
      await new Promise(function (r) { setTimeout(r, 1200); }); return send(res, 401, { error: 'wrong password' });
    }
    if (p !== '/' && !authed(req)) return send(res, 401, { error: 'auth' });
    if (p === '/stream') return pipeStream(req, res, u.searchParams.get('url'));
    try {
      if (p === '/') { if (indexPath && fs.existsSync(indexPath)) return send(res, 200, fs.readFileSync(indexPath), 'text/html'); return send(res, 200, '<body style="font-family:sans-serif;background:#0a0a0c;color:#fff;padding:30px"><h2>Shadow service is running</h2><p>Use the QR code in the TV app.</p>', 'text/html'); }
      if (p === '/hls') {
        const t0 = u.searchParams.get('url'), r = await hfetch(t0, { headers: { 'User-Agent': UA } });
        if (r.buf.slice(0, 7).toString() === '#EXTM3U') {
          const txt = r.text().split(/\r?\n/).map(function (l) {
            if (!l) return l; const enc = function (x) { return '/hls?url=' + encodeURIComponent(new URL(x, t0).href); };
            return l[0] === '#' ? l.replace(/URI="([^"]+)"/g, function (m, x) { return 'URI="' + enc(x) + '"'; }) : enc(l);
          }).join('\n');
          return send(res, 200, txt, 'application/vnd.apple.mpegurl');
        }
        return send(res, r.status, r.buf, r.headers['content-type'] || 'video/mp2t');
      }
      if (p === '/proxy') { const r = await hfetch(u.searchParams.get('url'), { headers: { 'User-Agent': UA } }); return send(res, r.status, r.buf, r.headers['content-type'] || 'text/plain'); }
      if (p === '/stalker/channels') return send(res, 200, await channels(await body(req)));
      if (p === '/stalker/link') return send(res, 200, await link(await body(req)));
      if (p === '/pair/new') {
        const code = String(Math.floor(100000 + Math.random() * 900000)); pairs[code] = { t: Date.now() };
        Object.keys(pairs).forEach(k => { if (Date.now() - pairs[k].t > 6e5) delete pairs[k]; });
        return send(res, 200, { code: code, url: 'http://' + (ip() || req.headers.host.split(':')[0]) + ':' + req.socket.localPort + '/pair?c=' + code });
      }
      if (p === '/pair') return send(res, 200, PAGE, 'text/html');
      if (p === '/pair/submit') { const b = await body(req); if (!pairs[b.code]) return send(res, 410, { error: 'expired' }); pairs[b.code].acc = b.acc; return send(res, 200, { ok: 1 }); }
      if (p === '/pair/poll') { const c = u.searchParams.get('c'), e = pairs[c]; if (e && e.acc) { delete pairs[c]; return send(res, 200, { acc: e.acc }); } return send(res, 200, {}); }
      send(res, 404, { error: 'not found' });
    } catch (e) { send(res, 500, { error: e.message }); }
  });
  srv.on('error', function (e) { console.log('server error', e.message); });
  srv.listen(port, '0.0.0.0'); return srv;
}
module.exports = { start: start, ip: ip };
