"""
Terminal Dashboard
-------------------
Live terminal view of all incoming interactions.
Updates in real-time as DNS/HTTP/SMTP callbacks arrive.
"""

import time
import threading
import sys
import os
from ..store import STORE

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[94m"
C = "\033[96m"; DIM = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"
CLEAR_LINE = "\033[2K\r"
UP = "\033[A"

PROTO_COLOR = {
    "dns":   G,
    "http":  C,
    "https": B,
    "smtp":  Y,
    "ftp":   Y,
}


def _proto_badge(proto: str) -> str:
    col = PROTO_COLOR.get(proto, DIM)
    return f"{col}{BOLD}[{proto.upper():<5}]{RST}"


def print_banner(domain: str, ports: dict):
    print(f"""
{R}
  ╔══════════════════════════════════════════════════════════╗
  ║         SSRF CALLBACK SERVER  —  by Z33                  ║
  ║         Burp Collaborator Alternative                    ║
  ╚══════════════════════════════════════════════════════════╝
{RST}
  {C}Callback Domain{RST} : {domain or '(not set — use --domain)'}
  {C}Listeners{RST}       : {', '.join(f'{p}:{v}' for p, v in ports.items() if v)}

  {Y}Waiting for interactions...{RST}
  {DIM}─────────────────────────────────────────────────────────{RST}
""")


def print_interaction(interaction) -> None:
    """Pretty-print a single interaction."""
    badge    = _proto_badge(interaction.protocol)
    ts       = time.strftime("%H:%M:%S", time.gmtime(interaction.timestamp))
    corr_tag = f" {Y}[{interaction.correlation}]{RST}" if interaction.correlation else ""
    meta_tag = ""

    if interaction.data.get("metadata_hit"):
        meta_tag = f" {R}{BOLD}★ CLOUD METADATA ★{RST}"

    print(f"  {badge} {DIM}{ts}{RST} {interaction.source_ip:<15}{corr_tag}{meta_tag}")

    d = interaction.data
    if interaction.protocol == "dns":
        print(f"         {DIM}Query:{RST} {d.get('query_name', '')} "
              f"({d.get('query_type', '')})")
    elif interaction.protocol in ("http", "https"):
        print(f"         {DIM}Method:{RST} {d.get('method', '')}  "
              f"{DIM}Host:{RST} {d.get('host', '')}  "
              f"{DIM}Path:{RST} {d.get('path', '')[:50]}")
        ua = d.get("user_agent", "")
        if ua:
            print(f"         {DIM}UA:{RST} {ua[:70]}")
    elif interaction.protocol == "smtp":
        cmds = d.get("commands", [])
        if cmds:
            print(f"         {DIM}SMTP:{RST} {' | '.join(cmds[:3])}")

    print()


def live_dashboard(poll_interval: float = 0.5):
    """
    Run a live dashboard that prints new interactions as they arrive.
    Blocks until Ctrl+C.
    """
    last_seen = time.time()
    counts    = {"total": 0, "dns": 0, "http": 0, "https": 0, "smtp": 0}

    print(f"\n  {DIM}─── Live Feed ──────────────────────────────────────────{RST}\n")

    def on_interaction(interaction):
        print_interaction(interaction)
        counts["total"] += 1
        counts[interaction.protocol] = counts.get(interaction.protocol, 0) + 1

    STORE.register_callback(on_interaction)

    try:
        while True:
            time.sleep(poll_interval)
    except KeyboardInterrupt:
        print(f"\n\n  {C}Session Summary:{RST}")
        c = STORE.count()
        print(f"    Total interactions : {c['total']}")
        print(f"    DNS                : {c['dns']}")
        print(f"    HTTP               : {c['http']}")
        print(f"    HTTPS              : {c['https']}")
        print(f"    SMTP               : {c['smtp']}")
        print()


def print_summary():
    """Print summary of all received interactions."""
    interactions = STORE.get_all()
    if not interactions:
        print(f"\n  {DIM}No interactions received yet.{RST}\n")
        return

    print(f"\n  {C}{BOLD}All Interactions ({len(interactions)} total){RST}\n")
    print(f"  {'#':<4} {'Proto':<7} {'Time':<10} {'Source IP':<16} "
          f"{'Correlation':<14} {'Detail'}")
    print(f"  {'─'*75}")

    for i, inter in enumerate(interactions, 1):
        ts      = time.strftime("%H:%M:%S", time.gmtime(inter.timestamp))
        corr    = inter.correlation or "-"
        proto   = PROTO_COLOR.get(inter.protocol, DIM) + inter.protocol.upper() + RST

        if inter.protocol == "dns":
            detail = inter.data.get("query_name", "")[:35]
        elif inter.protocol in ("http", "https"):
            detail = f"{inter.data.get('method','')} {inter.data.get('path','')}"[:35]
        else:
            detail = str(inter.data)[:35]

        meta = f" {R}★{RST}" if inter.data.get("metadata_hit") else ""

        print(f"  {i:<4} {proto:<14} {ts:<10} {inter.source_ip:<16} "
              f"{corr:<14} {detail}{meta}")

    print()
