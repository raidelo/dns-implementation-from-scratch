from random import randint

from utils import get_bits


QTYPE_MAPPING = {
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

QCLASS_MAPPING = {
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
        return QTYPE_MAPPING[qtype]
    except KeyError:
        print("error: qtype inválido")
        exit(1)


def get_qclass_encoded(qclass: str) -> int:
    try:
        return QCLASS_MAPPING[qclass]
    except KeyError:
        print("error: qclass inválido")
        exit(1)


def int_to_bytes(i: int) -> bytes:
    b = []
    while i != 0:
        b.append(i & 0b11111111)
        i >>= 8
    return bytes(b)
