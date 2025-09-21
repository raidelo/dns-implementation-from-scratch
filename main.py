from argparse import ArgumentParser
from random import randint
import re
import socket

SERVER_ADDRESS = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(\d{1,5}))?$")
DEFAULT_REMOTE_PORT = 53

CHUNK = 64

qtype_mapping = {
    "A": 1,  # a host address
    "NS": 2,  # an authoritative name server
    "MD": 3,  # a mail destination (Obsolete - use MX)
    "MF": 4,  # a mail forwarder (Obsolete - use MX)
    "CNAME": 5,  # the canonical name for an alias
    "SOA": 6,  # marks the start of a zone of authority
    "MB": 7,  # a mailbox domain name (EXPERIMENTAL)
    "MG": 8,  # a mail group member (EXPERIMENTAL)
    "MR": 9,  # a mail rename domain name (EXPERIMENTAL)
    "NULL": 10,  # a null RR (EXPERIMENTAL)
    "WKS": 11,  # a well known service description
    "PTR": 12,  # a domain name pointer
    "HINFO": 13,  # host information
    "MINFO": 14,  # mailbox or mail list information
    "MX": 15,  # mail exchange
    "TXT": 16,  # text strings
}

qclass_mapping = {
    "IN": 1,  # the Internet
    "CS": 2,  # the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    "CH": 3,  # the CHAOS class
    "HS": 4,  # Hesiod [Dyer 87]
}


def create_headers(domains: list[str], recursive: bool = True) -> bytes:
    id = randint(0, 2**16).to_bytes(2)  # ID
    qr_opcode_aa_tc_rd_ra_z_rcode = int(
        "".join(
            [
                "0",  # QR
                "0000",  # Opcode
                "0",  # AA
                "0",  # TC
                str(1 if recursive else 0),  # RD
                "0",  # RA
                "000",  # FUTURE USE
                "0000",  # RCODE
            ]
        ),
        2,
    ).to_bytes(2)
    qdcount = len(domains).to_bytes(2)
    ancount = int("0" * 16, 2).to_bytes(2)
    nscount = int("0" * 16, 2).to_bytes(2)
    arcount = int("0" * 16, 2).to_bytes(2)

    ret = id

    for i in [qr_opcode_aa_tc_rd_ra_z_rcode, qdcount, ancount, nscount, arcount]:
        ret += i

    return ret


def get_domain_encoded(domain: str):
    ret = b""
    for part in domain.split("."):
        ret += len(part).to_bytes()
        ret += part.encode()
    return ret + b"\x00"


def get_qtype_encoded(qtype: str) -> bytes:
    try:
        return qtype_mapping[qtype].to_bytes()
    except KeyError:
        print("error: qtype inválido")
        exit(1)


def get_qclass_encoded(qclass: str) -> bytes:
    try:
        return qclass_mapping[qclass].to_bytes()
    except KeyError:
        print("error: qclass inválido")
        exit(1)


def create_query(domain: bytes, qtype: bytes, qclass: bytes) -> bytes:
    ret = domain
    ret += qtype
    ret += qclass
    return ret


def create_request(
    domains: list[str], qtype: str = "A", qclass: str = "IN", recursive: bool = True
):
    ret = create_headers(domains, recursive)
    for domain in domains:
        query = create_query(
            get_domain_encoded(domain),
            get_qtype_encoded(qtype),
            get_qclass_encoded(qclass),
        )
        ret += query
    return ret


def get_bits(integer: int, left_padding: int | None = None) -> str:
    bits = bin(integer).replace("0b", "")
    if left_padding:
        return bits.zfill(left_padding)
    left_padding = 8
    while True:
        if len(bits) == left_padding:
            return bits
        elif len(bits) < left_padding:
            return bits.zfill(left_padding)
        else:
            left_padding += 8


def parse_server_string(address: str) -> tuple[str, int] | None:
    match = SERVER_ADDRESS.match(address)
    if match:
        port = match.group(3)
        return (match.group(1), int(port) if port else DEFAULT_REMOTE_PORT)
    return None


def int_to_bytes(i: int) -> bytes:
    b = []
    while i != 0:
        b.append(i & 0b11111111)
        i >>= 8
    return bytes(b)


def send_request(request: bytes, server: tuple[str, int]) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    sock.sendto(request, server)

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


def main():
    parser = ArgumentParser()
    parser.add_argument("domains", nargs="+")
    parser.add_argument("-s", "--server", default="8.8.8.8:53", dest="server")
    parser.add_argument("-t", "--type", default="A", dest="type")
    parser.add_argument(
        "-n",
        "--non-recursive",
        action="store_true",
        default=False,
        dest="non_recursive",
    )

    args = parser.parse_args()

    data = create_request(args.domains, args.type)
    server = parse_server_string(args.server)

    if not server:
        print("error: Invalid server address format: {}".format(server))
        exit(1)

    response = send_request(data, server)
    print("Received:", response)

    response_parsed = parse_response(response)


if __name__ == "__main__":
    main()
