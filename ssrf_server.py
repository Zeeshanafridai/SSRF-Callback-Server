#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         SSRF CALLBACK SERVER  —  by 0xZ33                    ║
║      Burp Collaborator Alternative — Self-Hosted             ║
║      github.com/Zeeshanafridai/ssrf-callback-server          ║
╚══════════════════════════════════════════════════════════════╝

Two modes:
  server   — Start listeners (DNS + HTTP + HTTPS + SMTP + Dashboard)
  probe    — Actively test a target URL for SSRF
  payloads — Print all payload variants for a domain
"""

import argparse
import sys
import os
import time
import json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ssrf.store import STORE, build_payloads
from ssrf.listeners.http_listener import start_http_listener, start_https_listener
from ssrf.listeners.dns_listener import start_dns_listener
from ssrf.listeners.smtp_listener import start_smtp_listener
from ssrf.dashboard.terminal import print_banner, live_dashboard, print_summary
from ssrf.dashboard.web import start_web_dashboard
from ssrf.detectors.ssrf_probe import SSRFProbe

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; DIM = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"


def cmd_server(args):
    """Start all listeners and wait for callbacks."""
    domain   = args.domain or ""
    my_ip    = args.ip or "0.0.0.0"
    ports    = {}

    print_banner(domain, {
        "HTTP":      args.http_port,
        "HTTPS":     args.https_port if not args.no_https else None,
        "DNS":       args.dns_port,
        "SMTP":      args.smtp_port if not args.no_smtp else None,
        "Dashboard": args.dashboard_port,
    })

    # Start listeners
    if args.http_port:
        start_http_listener(args.http_port, domain, verbose=True)
        ports["http"] = args.http_port

    if args.https_port and not args.no_https:
        start_https_listener(args.https_port, domain, verbose=True)
        ports["https"] = args.https_port

    if args.dns_port:
        start_dns_listener(args.dns_port, domain,
                            respond_ip=my_ip, verbose=True)
        ports["dns"] = args.dns_port

    if args.smtp_port and not args.no_smtp:
        start_smtp_listener(args.smtp_port, verbose=True)
        ports["smtp"] = args.smtp_port

    if args.dashboard_port:
        start_web_dashboard(args.dashboard_port, domain, verbose=True)
        ports["dashboard"] = args.dashboard_port

    print(f"\n  {Y}[*]{RST} All listeners started. Waiting for interactions...")
    if domain:
        print(f"  {Y}[*]{RST} Use payloads containing: {G}{domain}{RST}")
        print(f"  {Y}[*]{RST} Run: python3 ssrf_server.py payloads --domain {domain}")
    print(f"\n  {DIM}Press Ctrl+C to stop and show summary{RST}\n")

    live_dashboard()


def cmd_probe(args):
    """Actively probe a target for SSRF."""
    if not args.domain:
        print(f"  {R}[!] --domain required for probe mode{RST}")
        sys.exit(1)

    print(f"\n{C}[SSRF PROBE MODE]{RST}")
    print(f"  Target   : {args.url}")
    print(f"  Domain   : {args.domain}")
    print(f"  Method   : {args.method}")
    print(f"  Wait     : {args.wait}s per probe\n")

    # Start minimal listeners to receive callbacks
    start_http_listener(args.http_port, args.domain, verbose=False)
    start_dns_listener(args.dns_port, args.domain, respond_ip="127.0.0.1", verbose=False)

    print(f"  {G}[*]{RST} Listeners ready on HTTP:{args.http_port} DNS:{args.dns_port}\n")

    probe = SSRFProbe(
        target_url      = args.url,
        callback_domain = args.domain,
        cookies         = args.cookies,
        method          = args.method,
        body            = args.data,
        content_type    = args.content_type,
        wait_seconds    = args.wait,
        verbose         = True,
    )

    params = args.param if args.param else None
    findings = probe.run_full_scan(
        params_to_test = params,
        test_headers   = not args.no_headers,
        payload_types  = args.payload_types,
    )

    if args.output:
        with open(args.output, "w") as f:
            json.dump(findings, f, indent=2, default=str)
        print(f"\n  {G}[+]{RST} Results saved to {args.output}")

    print_summary()


def cmd_payloads(args):
    """Print all payload variants for a domain."""
    if not args.domain:
        print(f"  {R}[!]{RST} --domain required")
        sys.exit(1)

    data = build_payloads(args.domain)
    print(f"\n{C}SSRF Payloads for: {data['domain']}{RST}")
    print(f"{DIM}Correlation ID: {data['correlation_id']}{RST}\n")

    categories = {
        "HTTP/HTTPS Callbacks": ["http_direct", "https_direct", "http_with_path", "http_with_data"],
        "DNS Only":             ["dns_only"],
        "Protocol Schemes":     ["scheme_dict", "scheme_gopher", "scheme_ftp", "scheme_ldap", "scheme_sftp"],
        "Cloud Metadata":       ["aws_metadata", "aws_imdsv2", "gcp_metadata", "azure_metadata", "azure_imds"],
        "Internal Ports":       ["localhost_6379", "localhost_5432", "localhost_27017",
                                  "localhost_9200", "localhost_8080"],
        "IP Bypasses":          ["decimal_ip", "octal_ip", "hex_ip", "ipv6_loopback",
                                  "ipv6_mapped", "short_domain"],
    }

    for cat, keys in categories.items():
        print(f"  {Y}{cat}{RST}")
        for k in keys:
            v = data["payloads"].get(k, "")
            if v:
                print(f"    {DIM}{k:<22}{RST} {v}")
        print()

    if args.output:
        with open(args.output, "w") as f:
            json.dump(data, f, indent=2)
        print(f"  {G}[+]{RST} Saved to {args.output}")


def main():
    parser = argparse.ArgumentParser(
        prog="ssrf-server",
        description="SSRF Callback Server — Burp Collaborator Alternative"
    )
    sub = parser.add_subparsers(dest="command")

    # ── SERVER MODE ────────────────────────────────────────────────────────
    sp = sub.add_parser("server", help="Start callback listeners")
    sp.add_argument("--domain",        help="Your callback domain (e.g. callback.yourserver.com)")
    sp.add_argument("--ip",            help="Your public IP (for DNS responses)")
    sp.add_argument("--http-port",     type=int, default=80)
    sp.add_argument("--https-port",    type=int, default=443)
    sp.add_argument("--dns-port",      type=int, default=53)
    sp.add_argument("--smtp-port",     type=int, default=25)
    sp.add_argument("--dashboard-port",type=int, default=8080)
    sp.add_argument("--no-https",      action="store_true")
    sp.add_argument("--no-smtp",       action="store_true")

    # ── PROBE MODE ─────────────────────────────────────────────────────────
    pp = sub.add_parser("probe", help="Actively test a URL for SSRF")
    pp.add_argument("-u", "--url",      required=True)
    pp.add_argument("--domain",         required=True, help="Your callback domain")
    pp.add_argument("-m", "--method",   default="GET")
    pp.add_argument("-d", "--data",     help="POST body")
    pp.add_argument("--content-type",   default="form", choices=["form", "json"])
    pp.add_argument("-c", "--cookies")
    pp.add_argument("-p", "--param",    action="append", help="Specific params to test")
    pp.add_argument("--no-headers",     action="store_true")
    pp.add_argument("--payload-types",  nargs="+")
    pp.add_argument("--wait",           type=int, default=10)
    pp.add_argument("--http-port",      type=int, default=8888)
    pp.add_argument("--dns-port",       type=int, default=5353)
    pp.add_argument("-o", "--output")

    # ── PAYLOADS MODE ──────────────────────────────────────────────────────
    plp = sub.add_parser("payloads", help="Generate payload list for a domain")
    plp.add_argument("--domain",        required=True)
    plp.add_argument("--corr",          help="Custom correlation ID")
    plp.add_argument("-o", "--output")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        print(f"\n  {Y}Quick start:{RST}")
        print(f"    {DIM}# Start server{RST}")
        print(f"    python3 ssrf_server.py server --domain callback.yourserver.com --ip YOUR_IP")
        print(f"    {DIM}# Generate payloads{RST}")
        print(f"    python3 ssrf_server.py payloads --domain callback.yourserver.com")
        print(f"    {DIM}# Probe a target{RST}")
        print(f"    python3 ssrf_server.py probe -u https://target.com/api?url= --domain callback.yourserver.com")
        sys.exit(0)

    if args.command == "server":
        cmd_server(args)
    elif args.command == "probe":
        cmd_probe(args)
    elif args.command == "payloads":
        cmd_payloads(args)


if __name__ == "__main__":
    main()
