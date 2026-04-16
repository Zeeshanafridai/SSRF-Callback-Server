"""
SSRF Detector
--------------
Actively probes target application parameters for SSRF vulnerabilities.
Sends payloads to every parameter and waits for callbacks.

Detection methods:
  1. Direct HTTP/DNS callback — most reliable
  2. Time-based — delayed response indicates internal request
  3. Error-based — internal hostnames/IPs in error messages
  4. Blind OOB — DNS-only for strict egress environments

Injection points tested:
  - URL query parameters
  - POST body (form + JSON)
  - HTTP headers (Referer, X-Forwarded-For, Host, etc.)
  - File upload URLs
  - Import/webhook URL fields
  - PDF/image rendering endpoints
"""

import urllib.request
import urllib.parse
import urllib.error
import ssl
import json
import time
import threading
from ..store import STORE, build_payloads, generate_correlation_id

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; DIM = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"

SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE

DEFAULT_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Headers that commonly carry URLs (SSRF via header injection)
SSRF_HEADERS = [
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Real-IP",
    "X-Original-URL",
    "X-Rewrite-URL",
    "Referer",
    "Origin",
    "True-Client-IP",
    "CF-Connecting-IP",
    "X-Custom-IP-Authorization",
    "X-Host",
    "X-Remote-IP",
    "Client-IP",
    "Forwarded",
    "X-ProxyUser-Ip",
    "Via",
    "X-Wap-Profile",
    "X-ATT-DeviceId",
    "Contact",
    "X-Requested-With",
]

# Common parameter names that accept URLs
URL_PARAMS = [
    "url", "uri", "link", "href", "src", "source",
    "redirect", "return", "next", "back", "forward",
    "target", "destination", "dest", "to",
    "fetch", "load", "import", "include",
    "webhook", "callback", "notify", "ping",
    "feed", "rss", "proxy", "endpoint",
    "api", "service", "host", "server",
    "file", "path", "resource", "asset",
    "image", "img", "avatar", "thumbnail", "preview",
    "pdf", "doc", "document", "export",
    "data", "content", "body", "payload",
    "open", "navigate", "location", "page",
]


def _http_request(url: str, method: str = "GET", headers: dict = None,
                   data: dict = None, json_body: dict = None,
                   cookies: str = None, timeout: int = 10) -> dict:
    req_headers = {"User-Agent": DEFAULT_UA}
    if headers:
        req_headers.update(headers)
    if cookies:
        req_headers["Cookie"] = cookies

    body_bytes = None
    if json_body:
        body_bytes = json.dumps(json_body).encode()
        req_headers["Content-Type"] = "application/json"
    elif data:
        body_bytes = urllib.parse.urlencode(data).encode()
        req_headers["Content-Type"] = "application/x-www-form-urlencoded"

    try:
        req = urllib.request.Request(url, data=body_bytes,
                                      headers=req_headers, method=method)
        opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=SSL_CTX)
        )
        start = time.perf_counter()
        with opener.open(req, timeout=timeout) as resp:
            elapsed = time.perf_counter() - start
            body = resp.read(65536).decode("utf-8", errors="replace")
            return {"status": resp.status, "body": body,
                    "elapsed": elapsed, "error": None}
    except Exception as e:
        elapsed = time.perf_counter() - start if "start" in dir() else 0
        return {"status": 0, "body": "", "elapsed": elapsed, "error": str(e)}


class SSRFProbe:
    """
    Probes a single URL/parameter combination for SSRF.
    """

    def __init__(self, target_url: str, callback_domain: str,
                  cookies: str = None, method: str = "GET",
                  body: str = None, content_type: str = "form",
                  wait_seconds: int = 10, verbose: bool = True):
        self.target_url      = target_url
        self.callback_domain = callback_domain
        self.cookies         = cookies
        self.method          = method.upper()
        self.body            = body
        self.content_type    = content_type
        self.wait_seconds    = wait_seconds
        self.verbose         = verbose
        self.findings        = []

    def probe_param(self, param_name: str, payload_url: str,
                     corr_id: str) -> dict:
        """Inject payload_url into param_name and check for callback."""
        before_count = STORE.count()["total"]

        if self.method == "GET":
            # Parse existing params and inject
            parsed   = urllib.parse.urlparse(self.target_url)
            existing = dict(urllib.parse.parse_qsl(parsed.query))
            existing[param_name] = payload_url
            new_qs   = urllib.parse.urlencode(existing)
            test_url = urllib.parse.urlunparse(parsed._replace(query=new_qs))
            resp     = _http_request(test_url, cookies=self.cookies)
        else:
            # POST body injection
            if self.content_type == "json":
                body_data = {}
                if self.body:
                    try:
                        body_data = json.loads(self.body)
                    except Exception:
                        pass
                body_data[param_name] = payload_url
                resp = _http_request(self.target_url, method=self.method,
                                      json_body=body_data, cookies=self.cookies)
            else:
                form_data = {}
                if self.body:
                    form_data = dict(urllib.parse.parse_qsl(self.body))
                form_data[param_name] = payload_url
                resp = _http_request(self.target_url, method=self.method,
                                      data=form_data, cookies=self.cookies)

        # Wait for callback
        interaction = STORE.wait_for(corr_id, timeout=self.wait_seconds)

        result = {
            "param":       param_name,
            "payload":     payload_url,
            "corr_id":     corr_id,
            "http_status": resp.get("status"),
            "vulnerable":  interaction is not None,
            "callback":    interaction.to_dict() if interaction else None,
            "response_time": resp.get("elapsed"),
        }

        if interaction:
            result["protocol"] = interaction.protocol
            if self.verbose:
                print(f"\n  {R}{BOLD}[!!!] SSRF CONFIRMED{RST}")
                print(f"        Param    : {param_name}")
                print(f"        Payload  : {payload_url[:70]}")
                print(f"        Protocol : {interaction.protocol.upper()}")
                print(f"        From IP  : {interaction.source_ip}")
                if interaction.data.get("metadata_hit"):
                    print(f"        {R}CLOUD METADATA HIT: {interaction.data['metadata_hit']}{RST}")
                print()

        return result

    def probe_header(self, header_name: str, payload_url: str,
                      corr_id: str) -> dict:
        """Inject SSRF payload into an HTTP header."""
        headers = {header_name: payload_url}
        resp = _http_request(self.target_url, headers=headers,
                              cookies=self.cookies)

        interaction = STORE.wait_for(corr_id, timeout=self.wait_seconds)

        return {
            "param":      f"header:{header_name}",
            "payload":    payload_url,
            "corr_id":    corr_id,
            "vulnerable": interaction is not None,
            "callback":   interaction.to_dict() if interaction else None,
        }

    def run_full_scan(self, params_to_test: list = None,
                       test_headers: bool = True,
                       payload_types: list = None) -> list:
        """
        Full SSRF scan on target URL.
        Tests all URL params, common URL-like params, and headers.
        """
        all_findings = []

        # Build payload set
        payload_data = build_payloads(self.callback_domain)
        corr_id      = payload_data["correlation_id"]
        payloads     = payload_data["payloads"]

        # Select which payload types to use
        if payload_types:
            selected_payloads = {k: v for k, v in payloads.items() if k in payload_types}
        else:
            # Use primary probes by default
            primary = ["http_direct", "https_direct", "dns_only",
                        "scheme_dict", "scheme_gopher"]
            selected_payloads = {k: payloads[k] for k in primary if k in payloads}

        # Determine params to test
        if params_to_test is None:
            # Extract from URL + add common URL param names
            parsed   = urllib.parse.urlparse(self.target_url)
            url_params = list(dict(urllib.parse.parse_qsl(parsed.query)).keys())
            params_to_test = url_params + [p for p in URL_PARAMS if p not in url_params]

        if self.verbose:
            print(f"\n  {C}[SSRF SCAN]{RST} {self.target_url}")
            print(f"  Testing {len(params_to_test)} params × "
                  f"{len(selected_payloads)} payloads")
            print(f"  Callback: {payload_data['domain']}")
            print(f"  Waiting {self.wait_seconds}s per probe...\n")

        # Probe each param with each payload
        for param in params_to_test:
            for ptype, payload_url in selected_payloads.items():
                cid = generate_correlation_id()
                # Inject correlation into payload URL
                p_url = payload_url.replace(corr_id, cid) if corr_id in payload_url else payload_url

                if self.verbose:
                    print(f"  {DIM}[~]{RST} {param} ← {ptype}", end="\r")

                result = self.probe_param(param, p_url, cid)

                if result["vulnerable"]:
                    all_findings.append(result)
                    self.findings.append(result)
                    # Don't stop — find ALL vulnerable params

        # Probe headers
        if test_headers:
            if self.verbose:
                print(f"\n  {C}[*]{RST} Testing {len(SSRF_HEADERS)} headers...")

            for header in SSRF_HEADERS:
                cid   = generate_correlation_id()
                p_url = payloads["http_direct"].replace(corr_id, cid)

                result = self.probe_header(header, p_url, cid)
                if result["vulnerable"]:
                    all_findings.append(result)

        if self.verbose:
            print(f"\r{' '*60}\r", end="")
            if all_findings:
                print(f"\n  {R}{BOLD}[!!!] {len(all_findings)} SSRF vulnerability(ies) found!{RST}")
            else:
                print(f"\n  {DIM}[-] No callbacks received — target may not be vulnerable{RST}")
                print(f"  {DIM}    or firewalled egress. Check DNS-only probes.{RST}")

        return all_findings
