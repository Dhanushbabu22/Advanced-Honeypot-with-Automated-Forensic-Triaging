"""
Fake FTP service.

Speaks just enough FTP control-channel text (220 banner, USER/PASS replies)
to log credential-stuffing attempts. Always replies 530 (login incorrect).
No data channel, no filesystem, no real FTP functionality is implemented.

Run as: python3 -m honeypot.services.ftp_decoy --port 2121
"""
import argparse
import socket
import threading
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from honeypot.common.db import log_event, init_db

BANNER = b"220 (vsFTPd 3.0.5)\r\n"


def handle_client(conn, addr):
    ip, port = addr
    log_event("ftp", ip, port, "connect")
    username = None
    try:
        conn.settimeout(10)
        conn.sendall(BANNER)
        while True:
            data = conn.recv(1024)
            if not data:
                break
            line = data.decode(errors="replace").strip()
            log_event("ftp", ip, port, "command", raw_payload=line)
            upper = line.upper()
            if upper.startswith("USER "):
                username = line[5:].strip()
                conn.sendall(b"331 Please specify the password.\r\n")
            elif upper.startswith("PASS "):
                password = line[5:].strip()
                log_event("ftp", ip, port, "auth_attempt", username=username, password=password)
                conn.sendall(b"530 Login incorrect.\r\n")
            elif upper.startswith("QUIT"):
                conn.sendall(b"221 Goodbye.\r\n")
                break
            else:
                conn.sendall(b"502 Command not implemented.\r\n")
    except (socket.timeout, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        log_event("ftp", ip, port, "disconnect")
        conn.close()


def serve(host, port):
    init_db()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((host, port))
    srv.listen(50)
    print(f"[ftp_decoy] listening on {host}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--host", default="0.0.0.0")
    p.add_argument("--port", type=int, default=2121)
    args = p.parse_args()
    serve(args.host, args.port)
