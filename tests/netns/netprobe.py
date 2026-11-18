"""Tiny TCP/UDP servers and probes for the fwg traffic tests.

serve tcp|udp PORT...      serve on all IPv4 and IPv6 addresses until killed
probe tcp|udp HOST PORT    print OPEN, REFUSED (reset / port unreachable) or TIMEOUT
burst tcp HOST PORT N      N quick TCP probes, one result per line
"""

import socket
import sys
import threading

TIMEOUT_SECS = 0.7


def _dual_stack(kind: int, port: int) -> socket.socket:
    sock = socket.socket(socket.AF_INET6, kind)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", port))
    return sock


def _serve_tcp(port: int) -> None:
    sock = _dual_stack(socket.SOCK_STREAM, port)
    sock.listen(64)
    while True:
        conn, _ = sock.accept()
        conn.sendall(b"ok")
        conn.close()


def _serve_udp(port: int) -> None:
    sock = _dual_stack(socket.SOCK_DGRAM, port)
    while True:
        _, peer = sock.recvfrom(64)
        sock.sendto(b"ok", peer)


def serve(proto: str, ports: list[int]) -> None:
    target = _serve_tcp if proto == "tcp" else _serve_udp
    threads = [threading.Thread(target=target, args=(p,), daemon=True) for p in ports]
    for t in threads:
        t.start()
    print("ready", flush=True)
    threading.Event().wait()


def probe(proto: str, host: str, port: int) -> str:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    kind = socket.SOCK_STREAM if proto == "tcp" else socket.SOCK_DGRAM
    with socket.socket(family, kind) as sock:
        sock.settimeout(TIMEOUT_SECS)
        try:
            sock.connect((host, port))
            if proto == "udp":
                sock.send(b"ping")
            return "OPEN" if sock.recv(2) == b"ok" else "BROKEN"
        except ConnectionRefusedError:
            return "REFUSED"
        except (TimeoutError, socket.timeout):
            return "TIMEOUT"


def main(argv: list[str]) -> None:
    cmd, proto, *rest = argv
    if cmd == "serve":
        serve(proto, [int(p) for p in rest])
    elif cmd == "probe":
        print(probe(proto, rest[0], int(rest[1])))
    elif cmd == "burst":
        for _ in range(int(rest[2])):
            print(probe(proto, rest[0], int(rest[1])))
    else:
        sys.exit(f"unknown command {cmd}")


if __name__ == "__main__":
    main(sys.argv[1:])
