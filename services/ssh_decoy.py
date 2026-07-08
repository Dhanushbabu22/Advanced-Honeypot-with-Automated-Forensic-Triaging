"""
Fake SSH service.

This does NOT implement real SSH key exchange/encryption. It speaks just
enough of the SSH banner protocol to convince an automated scanner or
unauthenticated `ssh` client to send a protocol identification string and,
for simple credential-stuffing bots, a handful of plaintext username/password
guesses (many mass-scanning bots try raw guesses before falling back to a
proper handshake). Every byte received is logged. The connection is then
dropped. No shell, no real authentication, no real SSH protocol completion
ever occurs.

Run as: python3 -m honeypot.services.ssh_decoy --port 2222
(use a high port for local lab testing; do not run as root binding to 22
 on a host you don't own / outside an isolated lab network)
"""
import argparse
import socket
import threading
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from honeypot.common.db import log_event, init_db

BANNER = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4\r\n"


def handle_client(conn, addr):
    ip, port = addr
    log_event("ssh", ip, port, "connect")
    try:
        conn.settimeout(8)
        conn.sendall(BANNER)
        data = conn.recv(4096)
        if data:
            log_event("ssh", ip, port, "request", raw_payload=repr(data)[:1000])
        # Give scanners a moment to dump any follow-up (some bots send
        # plaintext creds as part of fuzzing/probing before bailing)
        conn.settimeout(3)
        try:
            more = conn.recv(4096)
            if more:
                log_event("ssh", ip, port, "command", raw_payload=repr(more)[:1000])
        except socket.timeout:
            pass
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        log_event("ssh", ip, port, "disconnect")
        conn.close()


def serve(host, port):
    init_db()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(50)
    print(f"[ssh_decoy] listening on {host}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=2222)
    args = p.parse_args()
    serve(args.host, args.port)
