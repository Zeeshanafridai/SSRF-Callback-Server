"""
DNS Listener
-------------
Captures DNS queries — the most reliable OOB channel.
Even firewalled servers resolve DNS.

Handles:
  - A record queries (most common)
  - AAAA (IPv6)
  - MX, TXT, CNAME lookups
  - Extracts correlation ID from subdomain label
  - Responds with our own IP so HTTP callback follows
"""

import socket
import struct
import threading
import time
import re
from ..store import STORE

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; DIM = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"

DNS_PORT = 53

# DNS query type codes
QTYPE_A    = 1
QTYPE_AAAA = 28
QTYPE_MX   = 15
QTYPE_TXT  = 16
QTYPE_CNAME= 5
QTYPE_ANY  = 255


def _parse_dns_name(data: bytes, offset: int) -> tuple:
    """Parse DNS name from packet, handling compression pointers."""
    labels = []
    jumped = False
    orig_offset = offset
    max_jumps = 10

    while max_jumps > 0:
        if offset >= len(data):
            break
        length = data[offset]

        if length == 0:
            offset += 1
            break
        elif (length & 0xC0) == 0xC0:
            # Pointer
            if offset + 1 >= len(data):
                break
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                orig_offset = offset + 2
            offset = ptr
            jumped = True
            max_jumps -= 1
        else:
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="replace"))
            offset += length

    name = ".".join(labels)
    return name, (orig_offset if jumped else offset)


def _build_dns_response(query_data: bytes, answer_ip: str = "127.0.0.1") -> bytes:
    """Build a minimal DNS A-record response."""
    try:
        # Header: transaction ID + flags + counts
        tx_id   = query_data[:2]
        flags   = struct.pack(">H", 0x8180)  # Standard response, recursion available
        qdcount = query_data[4:6]
        ancount = struct.pack(">H", 1)
        nscount = struct.pack(">H", 0)
        arcount = struct.pack(">H", 0)

        header = tx_id + flags + qdcount + ancount + nscount + arcount

        # Copy question section
        question = query_data[12:]

        # Build answer: pointer to name + type A + class IN + ttl + rdlength + rdata
        answer = (
            struct.pack(">H", 0xC00C) +       # name pointer to offset 12
            struct.pack(">H", QTYPE_A) +       # type A
            struct.pack(">H", 1) +             # class IN
            struct.pack(">I", 60) +            # TTL 60s
            struct.pack(">H", 4) +             # rdlength
            socket.inet_aton(answer_ip)        # IP
        )

        return header + question + answer
    except Exception:
        return b""


def _extract_corr_from_name(name: str, base_domain: str) -> str:
    """
    Extract correlation ID from DNS name.
    abc123def456.callback.attacker.com → abc123def456
    """
    if not base_domain:
        return None
    base_lower = base_domain.lower().rstrip(".")
    name_lower = name.lower().rstrip(".")

    if name_lower.endswith(f".{base_lower}") or name_lower == base_lower:
        subdomain = name_lower[:-(len(base_lower) + 1)] if name_lower != base_lower else ""
        parts = subdomain.split(".")
        # First label is usually the correlation ID
        for part in parts:
            if re.match(r"^[a-f0-9]{6,16}$", part):
                return part
    return None


class DNSListener:
    """UDP DNS listener that captures all incoming queries."""

    def __init__(self, port: int = 53, base_domain: str = "",
                 respond_ip: str = "127.0.0.1", verbose: bool = True):
        self.port        = port
        self.base_domain = base_domain
        self.respond_ip  = respond_ip
        self.verbose     = verbose
        self._sock       = None
        self._thread     = None
        self._running    = False

    def start(self) -> threading.Thread:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.port))
            self._sock.settimeout(1.0)
            self._running = True
            self._thread  = threading.Thread(target=self._serve, daemon=True)
            self._thread.start()

            if self.verbose:
                print(f"  {G}[DNS]{RST}   Listening on UDP port {self.port}")

            return self._thread
        except PermissionError:
            if self.verbose:
                print(f"  {Y}[DNS]{RST}   Port {self.port} requires root — trying 5353...")
            self.port = 5353
            return self.start()
        except Exception as e:
            if self.verbose:
                print(f"  {Y}[DNS]{RST}   Could not bind: {e}")
            return None

    def stop(self):
        self._running = False
        if self._sock:
            self._sock.close()

    def _serve(self):
        while self._running:
            try:
                data, addr = self._sock.recvfrom(512)
                self._handle_query(data, addr)
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    continue

    def _handle_query(self, data: bytes, addr: tuple):
        if len(data) < 12:
            return

        client_ip = addr[0]

        try:
            # Parse query
            name, offset = _parse_dns_name(data, 12)
            qtype = struct.unpack(">H", data[offset:offset + 2])[0] if offset + 2 <= len(data) else 0

            qtype_name = {
                QTYPE_A:    "A",
                QTYPE_AAAA: "AAAA",
                QTYPE_MX:   "MX",
                QTYPE_TXT:  "TXT",
                QTYPE_CNAME:"CNAME",
                QTYPE_ANY:  "ANY",
            }.get(qtype, f"TYPE{qtype}")

            corr = _extract_corr_from_name(name, self.base_domain)

            raw_data = {
                "query_name": name,
                "query_type": qtype_name,
                "correlation": corr,
                "protocol":   "dns",
            }

            interaction = STORE.add("dns", client_ip, raw_data)

            if self.verbose:
                corr_tag = f" {Y}corr={corr}{RST}" if corr else ""
                print(f"\n  {G}{BOLD}[DNS HIT]{RST}{corr_tag}")
                print(f"    From     : {client_ip}")
                print(f"    Query    : {name} ({qtype_name})")
                print()

            # Send response
            response = _build_dns_response(data, self.respond_ip)
            if response:
                self._sock.sendto(response, addr)

        except Exception:
            pass


def start_dns_listener(port: int = 53, base_domain: str = "",
                        respond_ip: str = "127.0.0.1",
                        verbose: bool = True) -> DNSListener:
    listener = DNSListener(port, base_domain, respond_ip, verbose)
    listener.start()
    return listener
