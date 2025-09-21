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


def create_headers(domains: list[str], recursive: bool = True) -> int:
    id = get_bits(randint(0, 65535), 16)  # ID
    qr_opcode_aa_tc_rd_ra_z_rcode = "".join(
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
    )
    qdcount = get_bits(len(domains), 16)
    ancount = "0" * 16
    nscount = "0" * 16
    arcount = "0" * 16

    ret = int(id, 2)

    for i in [qr_opcode_aa_tc_rd_ra_z_rcode, qdcount, ancount, nscount, arcount]:
        ret <<= 16
        ret |= int(i, 2)

    return ret


def get_domain_encoded(domain: str):
    ret = 0
    for part in domain.split("."):
        ret <<= 8
        ret |= len(part)
        for letter in part:
            ret <<= 8
            ret |= ord(letter)
    return ret << 8


def get_qtype_encoded(qtype: str) -> int:
    try:
        return qtype_mapping[qtype]
    except KeyError:
        print("error: qtype inválido")
        exit(1)


def get_qclass_encoded(qclass: str) -> int:
    try:
        return qclass_mapping[qclass]
    except KeyError:
        print("error: qclass inválido")
        exit(1)


def create_query(domain: int, qtype: int, qclass: int) -> int:
    ret = domain
    ret <<= 16
    ret |= qtype
    ret <<= 16
    ret |= qclass
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
        ret <<= len(get_bits(query))
        ret |= query
    return ret


def get_bits(data: int, left_padding: int | None = None) -> str:
    bits = bin(data).replace("0b", "")
    if left_padding:
        return bits.zfill(left_padding)
    left_padding = 8
    while True:
        if len(bits) <= left_padding:
            return bits.zfill(left_padding)
        else:
            left_padding += 8


def parse_server(address: str) -> tuple[str, int] | None:
    match = SERVER_ADDRESS.match(address)
    if match:
        port = match.group(3)
        return (match.group(1), int(port) if port else DEFAULT_REMOTE_PORT)
    return None


def parse_response(r: bytes) -> str:
    raise NotImplementedError


def int_to_bytes(i: int) -> bytes:
    b = []
    while i != 0:
        b.append(i & 0b11111111)
        i >>= 8
    return bytes(b)


def send_request(request: int, server: tuple[str, int]) -> bytes:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    to_send = int_to_bytes(request)

    sock.sendto(to_send, server)

    buf = b""

    recvd = sock.recv(CHUNK)

    while len(recvd) != 0:
        recvd += sock.recv(CHUNK)
        buf += recvd

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
    server = parse_server(args.server)

    if not server:
        print("error: Invalid server address format: {}".format(server))
        exit(1)

    response = send_request(data, server)
    print("Received:", response)

    response_parsed = parse_response(response)


if __name__ == "__main__":
    main()
