from argparse import ArgumentParser
import re
from random import randint
import socket

SERVER_ADDRESS = re.compile(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(:(\d{1,5}))?$")
DEFAULT_REMOTE_PORT = 53


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


def bin_to_int(s: str) -> int:
    return int(s, 2)


def create_headers(domains: list[str], recursive: bool = True) -> int:
    id = get_bits(randint(0, 65535)).zfill(16)  # ID
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

    qdcount = get_bits(len(domains)).zfill(16)
    ancount = "0" * 16
    nscount = "0" * 16
    arcount = "0" * 16

    to_return = int(id, 2)
    to_return <<= 16
    to_return |= int(qr_opcode_aa_tc_rd_ra_z_rcode, 2)
    to_return <<= 16
    to_return |= int(qdcount, 2)
    to_return <<= 16
    to_return |= int(ancount, 2)
    to_return <<= 16
    to_return |= int(nscount, 2)
    to_return <<= 16
    to_return |= int(arcount, 2)

    return to_return


def get_domain_encoded(domain: str):
    to_return = 0
    parts = domain.split(".")

    for part in parts:
        length = len(part)
        to_return <<= 8
        to_return |= length
        for letter in part:
            to_return <<= 8
            to_return |= ord(letter)
    return to_return << 8


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
    to_return = domain
    to_return <<= 16
    to_return |= qtype
    to_return <<= 16
    to_return |= qclass
    return to_return


def create_request(
    domains: list[str],
    qtype: str = "A",
    qclass: str = "IN",
):
    to_return = create_headers(domains, True)
    queries = []
    for domain in domains:
        domain_encoded = get_domain_encoded(domain)
        qtype_encoded = get_qtype_encoded(qtype)
        qclass_encoded = get_qclass_encoded(qclass)
        query_for_domain = create_query(domain_encoded, qtype_encoded, qclass_encoded)
        queries.append(query_for_domain)
    for query in queries:
        to_return <<= len(get_bits(query))
        to_return |= query
    return to_return


def send_request(request: int, server: tuple[str, int]) -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    bits = get_bits(request)

    to_send = bytes([int(bits[i : i + 8], 2) for i in range(0, len(bits), 8)])

    print("DataToSend:", to_send)

    sock.sendto(to_send, server)

    return sock.recv(50)


def get_bits(data: int) -> str:
    l_padding = 8
    binary_format = bin(data).replace("0b", "")
    while True:
        if len(binary_format) <= l_padding:
            return binary_format.zfill(l_padding)
        else:
            l_padding += 8


def parse_server(address: str) -> tuple[str, int] | None:
    match = SERVER_ADDRESS.match(address)
    if match:
        port = match.group(3)
        return (match.group(1), int(port) if port else DEFAULT_REMOTE_PORT)
    return None


def parse_response(r: bytes) -> str:
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
    server = parse_server(args.server)

    if not server:
        print("error: Invalid server address format: {}".format(server))
        exit(1)

    response = send_request(data, server)
    print("Received:", response)

    response_parsed = parse_response(response)


if __name__ == "__main__":
    main()
