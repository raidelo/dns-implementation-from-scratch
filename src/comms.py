import socket

from low import create_request


CHUNK = 65536
TIMEOUT = 3


def send_request(request: bytes, server: tuple[str, int]) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    sock.sendto(request, server)

    return sock.recv(CHUNK)


def send_query(
    server: tuple[str, int],
    domains: list[str],
    qtype: str = "A",
    qclass: str = "IN",
    recursive: bool = True,
) -> bytes:
    req = create_request(domains, qtype, qclass, recursive)
    return send_request(req, server)


def parse_response(r: bytes) -> dict:
    raise NotImplementedError
