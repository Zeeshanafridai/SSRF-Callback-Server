"""
SMTP Listener
--------------
Many apps send emails via internal SMTP — exploitable via SSRF.
Captures SMTP connections and commands.

Also useful for:
  - SSRF → SMTP relay pivoting
  - XXE → SSRF → internal SMTP
  - Log4Shell callbacks via SMTP
"""

import socket
import threading
import time
from ..store import STORE

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"
C = "\033[96m"; DIM = "\033[90m"; BOLD = "\033[1m"; RST = "\033[0m"


class SMTPHandler(threading.Thread):
    """Handles a single SMTP client connection."""

    def __init__(self, conn, addr, verbose: bool = True):
        super().__init__(daemon=True)
        self.conn    = conn
        self.addr    = addr
        self.verbose = verbose

    def run(self):
        client_ip = self.addr[0]
        commands  = []

        try:
            self.conn.settimeout(10)
            # Send banner
            self.conn.sendall(b"220 mail.internal.corp ESMTP\r\n")

            while True:
                try:
                    data = self.conn.recv(1024).decode("utf-8", errors="replace").strip()
                    if not data:
                        break
                    commands.append(data)

                    cmd = data.upper().split()[0] if data.split() else ""

                    if cmd == "EHLO" or cmd == "HELO":
                        self.conn.sendall(b"250-mail.internal.corp Hello\r\n250 OK\r\n")
                    elif cmd == "MAIL":
                        self.conn.sendall(b"250 OK\r\n")
                    elif cmd == "RCPT":
                        self.conn.sendall(b"250 OK\r\n")
                    elif cmd == "DATA":
                        self.conn.sendall(b"354 Start input\r\n")
                    elif cmd == "QUIT":
                        self.conn.sendall(b"221 Bye\r\n")
                        break
                    elif cmd == "STARTTLS":
                        self.conn.sendall(b"220 Ready\r\n")
                    else:
                        self.conn.sendall(b"250 OK\r\n")

                except socket.timeout:
                    break

        except Exception:
            pass
        finally:
            self.conn.close()

        raw_data = {
            "protocol":   "smtp",
            "commands":   commands,
            "correlation": None,
        }
        interaction = STORE.add("smtp", client_ip, raw_data)

        if self.verbose:
            print(f"\n  {G}{BOLD}[SMTP HIT]{RST}")
            print(f"    From     : {client_ip}")
            print(f"    Commands : {commands[:5]}")
            print()


class SMTPListener:
    def __init__(self, port: int = 25, verbose: bool = True):
        self.port    = port
        self.verbose = verbose
        self._sock   = None
        self._thread = None

    def start(self) -> threading.Thread:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.port))
            self._sock.listen(10)
            self._sock.settimeout(1.0)

            def serve():
                if self.verbose:
                    print(f"  {G}[SMTP]{RST}  Listening on port {self.port}")
                while True:
                    try:
                        conn, addr = self._sock.accept()
                        SMTPHandler(conn, addr, self.verbose).start()
                    except socket.timeout:
                        continue
                    except Exception:
                        break

            self._thread = threading.Thread(target=serve, daemon=True)
            self._thread.start()
            return self._thread
        except Exception as e:
            if self.verbose:
                print(f"  {Y}[SMTP]{RST}  Could not bind port {self.port}: {e}")
            return None


def start_smtp_listener(port: int = 25, verbose: bool = True) -> SMTPListener:
    listener = SMTPListener(port, verbose)
    listener.start()
    return listener
