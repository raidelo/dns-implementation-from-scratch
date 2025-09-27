import socket

from low import int_to_bytes, create_request


CHUNK = 64


def send_request(request: int, server: tuple[str, int]) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    to_send = int_to_bytes(request)

    sock.sendto(to_send, server)

    buf = b""

    recvd = sock.recv(CHUNK)

    while len(recvd) != 0:
        buf += recvd
        recvd = sock.recv(CHUNK)

    return buf


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
