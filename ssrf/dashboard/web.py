"""
Web Dashboard
--------------
Browser-based dashboard served on port 8080.
Auto-refreshes every 2s. Shows all interactions with full detail.
Pure Python — no external dependencies.
"""

import json
import time
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from ..store import STORE

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; DIM = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SSRF Callback Server — Z33</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0d0d0d; color: #e0e0e0; font-family: 'Courier New', monospace; }
  .header { background: #111; border-bottom: 1px solid #ff3333; padding: 16px 24px;
            display: flex; justify-content: space-between; align-items: center; }
  .header h1 { color: #ff3333; font-size: 18px; letter-spacing: 2px; }
  .header .meta { color: #666; font-size: 12px; }
  .stats { display: flex; gap: 12px; padding: 16px 24px; background: #111; }
  .stat { background: #1a1a1a; border: 1px solid #333; border-radius: 4px;
          padding: 10px 16px; min-width: 100px; }
  .stat .label { color: #666; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; }
  .stat .value { color: #00ff88; font-size: 24px; font-weight: bold; margin-top: 4px; }
  .stat.dns .value { color: #00cc44; }
  .stat.http .value { color: #00aaff; }
  .stat.https .value { color: #0066ff; }
  .stat.smtp .value { color: #ffaa00; }
  .container { padding: 16px 24px; }
  .interaction { background: #1a1a1a; border: 1px solid #2a2a2a; border-radius: 4px;
                  margin-bottom: 8px; padding: 12px 16px; transition: border-color 0.2s; }
  .interaction:hover { border-color: #ff3333; }
  .interaction.new { border-color: #ff3333; animation: pulse 1s ease-out; }
  .interaction.dns { border-left: 3px solid #00cc44; }
  .interaction.http { border-left: 3px solid #00aaff; }
  .interaction.https { border-left: 3px solid #0066ff; }
  .interaction.smtp { border-left: 3px solid #ffaa00; }
  .interaction.meta { border-left: 3px solid #ff3333; background: #1a0a0a; }
  @keyframes pulse { 0% { background: #2a1a1a; } 100% { background: #1a1a1a; } }
  .int-header { display: flex; gap: 12px; align-items: center; margin-bottom: 6px; }
  .badge { font-size: 10px; font-weight: bold; padding: 2px 6px; border-radius: 2px;
           text-transform: uppercase; letter-spacing: 1px; }
  .badge.dns   { background: #003311; color: #00cc44; }
  .badge.http  { background: #002244; color: #00aaff; }
  .badge.https { background: #001133; color: #0066ff; }
  .badge.smtp  { background: #332200; color: #ffaa00; }
  .badge.meta  { background: #330000; color: #ff3333; }
  .source-ip { color: #aaa; font-size: 13px; }
  .timestamp { color: #555; font-size: 12px; margin-left: auto; }
  .corr { background: #222; color: #ffcc00; padding: 1px 6px; border-radius: 2px;
          font-size: 11px; }
  .details { font-size: 12px; color: #888; }
  .details span { color: #aaa; }
  .details .key { color: #555; }
  .meta-alert { color: #ff3333; font-weight: bold; font-size: 13px; margin-top: 4px; }
  .empty { text-align: center; color: #333; padding: 60px; font-size: 14px; }
  .toolbar { display: flex; gap: 8px; margin-bottom: 12px; }
  .btn { background: #1a1a1a; border: 1px solid #333; color: #888; padding: 6px 12px;
         cursor: pointer; font-size: 12px; border-radius: 2px; font-family: monospace; }
  .btn:hover { border-color: #ff3333; color: #ff3333; }
  .filter { background: #1a1a1a; border: 1px solid #333; color: #aaa; padding: 6px 12px;
             font-size: 12px; border-radius: 2px; font-family: monospace; width: 200px; }
  .poll-indicator { width: 8px; height: 8px; border-radius: 50%; background: #00cc44;
                    display: inline-block; margin-right: 6px; animation: blink 2s infinite; }
  @keyframes blink { 0%,100% { opacity:1; } 50% { opacity:0.3; } }
  .payloads-panel { background: #111; border: 1px solid #333; border-radius: 4px;
                    padding: 16px; margin-bottom: 16px; display: none; }
  .payloads-panel h3 { color: #ff3333; margin-bottom: 12px; font-size: 13px; }
  .payload-item { display: flex; gap: 8px; margin-bottom: 6px; align-items: center; }
  .payload-label { color: #666; font-size: 11px; min-width: 160px; }
  .payload-url { color: #00aaff; font-size: 11px; cursor: pointer; }
  .payload-url:hover { text-decoration: underline; }
  code { background: #222; padding: 1px 4px; border-radius: 2px; color: #00aaff; font-size: 11px; }
</style>
</head>
<body>
<div class="header">
  <h1>⚡ SSRF CALLBACK SERVER</h1>
  <div class="meta">
    <span class="poll-indicator"></span>
    <span id="poll-status">Polling...</span>
    &nbsp;|&nbsp; Domain: <code id="domain-display">loading...</code>
  </div>
</div>

<div class="stats">
  <div class="stat"><div class="label">Total</div><div class="value" id="s-total">0</div></div>
  <div class="stat dns"><div class="label">DNS</div><div class="value" id="s-dns">0</div></div>
  <div class="stat http"><div class="label">HTTP</div><div class="value" id="s-http">0</div></div>
  <div class="stat https"><div class="label">HTTPS</div><div class="value" id="s-https">0</div></div>
  <div class="stat smtp"><div class="label">SMTP</div><div class="value" id="s-smtp">0</div></div>
</div>

<div class="container">
  <div class="toolbar">
    <button class="btn" onclick="clearAll()">🗑 Clear</button>
    <button class="btn" onclick="exportJSON()">📥 Export JSON</button>
    <button class="btn" onclick="togglePayloads()">📋 Show Payloads</button>
    <input class="filter" id="filter-input" placeholder="Filter by IP/corr/path..."
           oninput="filterInteractions()">
  </div>

  <div class="payloads-panel" id="payloads-panel">
    <h3>Generated Payloads (click to copy)</h3>
    <div id="payloads-list">Loading...</div>
  </div>

  <div id="interactions-container">
    <div class="empty">Waiting for callbacks...<br><br>
      Send a payload to your callback domain and watch here.
    </div>
  </div>
</div>

<script>
let allInteractions = [];
let lastPoll = 0;
let filterText = '';

async function poll() {
  try {
    const r = await fetch('/api/interactions?since=' + lastPoll);
    const data = await r.json();

    if (data.interactions && data.interactions.length > 0) {
      data.interactions.forEach(i => {
        allInteractions.unshift(i); // newest first
        lastPoll = Math.max(lastPoll, i.timestamp);
      });
      render();
    }

    // Update stats
    const sr = await fetch('/api/stats');
    const stats = await sr.json();
    document.getElementById('s-total').textContent = stats.total;
    document.getElementById('s-dns').textContent = stats.dns;
    document.getElementById('s-http').textContent = stats.http;
    document.getElementById('s-https').textContent = stats.https;
    document.getElementById('s-smtp').textContent = stats.smtp;
    document.getElementById('domain-display').textContent = stats.domain || 'not set';
    document.getElementById('poll-status').textContent = 'Live';

  } catch(e) {
    document.getElementById('poll-status').textContent = 'Disconnected';
  }

  setTimeout(poll, 2000);
}

function render() {
  const container = document.getElementById('interactions-container');
  const filtered = filterText
    ? allInteractions.filter(i =>
        JSON.stringify(i).toLowerCase().includes(filterText.toLowerCase()))
    : allInteractions;

  if (filtered.length === 0) {
    container.innerHTML = '<div class="empty">Waiting for callbacks...<br><br>Send a payload to your callback domain.</div>';
    return;
  }

  container.innerHTML = filtered.map((i, idx) => {
    const isMeta = i.data && i.data.metadata_hit;
    const isNew  = (Date.now()/1000 - i.timestamp) < 5;
    const cls    = ['interaction', i.protocol, isMeta ? 'meta' : '', isNew ? 'new' : ''].join(' ');
    const ts     = new Date(i.timestamp * 1000).toLocaleTimeString();
    const corr   = i.correlation ? `<span class="corr">${i.correlation}</span>` : '';
    const metaAlert = isMeta ? `<div class="meta-alert">🔥 CLOUD METADATA HIT: ${i.data.metadata_hit}</div>` : '';

    let detail = '';
    if (i.protocol === 'dns') {
      detail = `<span class="key">query:</span> <span>${i.data.query_name || ''}</span> (${i.data.query_type || ''})`;
    } else if (i.protocol === 'http' || i.protocol === 'https') {
      detail = `<span class="key">host:</span> <span>${i.data.host || ''}</span>
               &nbsp;&nbsp;<span class="key">path:</span> <span>${(i.data.path||'').substring(0,60)}</span>`;
      if (i.data.user_agent) detail += `<br><span class="key">ua:</span> <span>${i.data.user_agent.substring(0,80)}</span>`;
    } else if (i.protocol === 'smtp') {
      detail = `<span class="key">cmds:</span> <span>${(i.data.commands||[]).slice(0,3).join(' | ')}</span>`;
    }

    return `<div class="${cls}">
      <div class="int-header">
        <span class="badge ${isMeta ? 'meta' : i.protocol}">${i.protocol}</span>
        <span class="source-ip">${i.source_ip}</span>
        ${corr}
        <span class="timestamp">${ts}</span>
      </div>
      ${metaAlert}
      <div class="details">${detail}</div>
    </div>`;
  }).join('');
}

function filterInteractions() {
  filterText = document.getElementById('filter-input').value;
  render();
}

async function clearAll() {
  await fetch('/api/clear', {method:'POST'});
  allInteractions = [];
  lastPoll = 0;
  render();
}

function exportJSON() {
  const blob = new Blob([JSON.stringify(allInteractions, null, 2)], {type:'application/json'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'ssrf_interactions_' + Date.now() + '.json';
  a.click();
}

async function togglePayloads() {
  const panel = document.getElementById('payloads-panel');
  if (panel.style.display === 'block') {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = 'block';
  const r = await fetch('/api/payloads');
  const data = await r.json();
  const list = document.getElementById('payloads-list');
  list.innerHTML = Object.entries(data.payloads || {}).map(([k,v]) =>
    `<div class="payload-item">
       <span class="payload-label">${k}</span>
       <span class="payload-url" onclick="navigator.clipboard.writeText('${v}')" title="Click to copy">${v}</span>
     </div>`
  ).join('');
}

poll();
</script>
</body>
</html>"""


class DashboardHandler(BaseHTTPRequestHandler):

    callback_domain = ""

    def do_GET(self):
        if self.path == "/" or self.path == "/dashboard":
            self._serve_html()
        elif self.path.startswith("/api/interactions"):
            self._serve_interactions()
        elif self.path == "/api/stats":
            self._serve_stats()
        elif self.path.startswith("/api/payloads"):
            self._serve_payloads()
        else:
            self._404()

    def do_POST(self):
        if self.path == "/api/clear":
            STORE.clear()
            self._json({"ok": True})

    def _serve_html(self):
        body = DASHBOARD_HTML.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_interactions(self):
        import urllib.parse as up
        qs      = up.parse_qs(up.urlparse(self.path).query)
        since   = float(qs.get("since", ["0"])[0])
        items   = STORE.poll(since=since)
        data    = {"interactions": [i.to_dict() for i in items]}
        self._json(data)

    def _serve_stats(self):
        c = STORE.count()
        c["domain"] = self.callback_domain
        self._json(c)

    def _serve_payloads(self):
        from ..store import build_payloads
        data = build_payloads(self.callback_domain or "your-callback-domain.com")
        self._json(data)

    def _404(self):
        self.send_response(404)
        self.end_headers()

    def _json(self, data: dict):
        import json as _json
        body = _json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


def start_web_dashboard(port: int = 8080, callback_domain: str = "",
                          verbose: bool = True) -> threading.Thread:
    DashboardHandler.callback_domain = callback_domain

    class QuietServer(HTTPServer):
        def handle_error(self, request, client_address):
            pass

    server = QuietServer(("0.0.0.0", port), DashboardHandler)

    def serve():
        if verbose:
            print(f"  {G}[WEB]{RST}   Dashboard at http://localhost:{port}")
        server.serve_forever()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return t
