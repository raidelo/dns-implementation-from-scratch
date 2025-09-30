from random import randint
from collections import OrderedDict


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


def create_headers(domains: list[str], recursive: bool = True) -> bytes:
    id = randint(0, 2**16 - 1).to_bytes(2)  # ID
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

    return b"".join(
        [id, qr_opcode_aa_tc_rd_ra_z_rcode, qdcount, ancount, nscount, arcount]
    )


def create_query(domain: bytes, qtype: bytes, qclass: bytes) -> bytes:
    return b"".join([domain, qtype, qclass])


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
    request_len = len(ret)
    if request_len > 512:
        raise OverflowError(
            f"Invalid request length of {request_len} bytes. Maximum length is 512 bytes."
        )
    return ret


def get_domain_encoded(domain: str) -> bytes:
    ret = b""
    for sub_domain in domain.split("."):
        sub_domain_len = len(sub_domain)
        if sub_domain_len > 63:
            raise OverflowError(
                f"Invalid sub-domain length of {sub_domain_len} bytes. Maximum length is 63 bytes."
            )
        ret += sub_domain_len.to_bytes() + sub_domain.encode()
    ret += b"\x00"
    domain_name_len = len(ret)
    if domain_name_len > 255:
        raise OverflowError(
            f"Invalid domain name length of {domain_name_len} bytes. Maximum length is 255 bytes."
        )
    return ret


def get_qtype_encoded(qtype: str) -> bytes:
    try:
        return QTYPE_MAPPING[qtype].to_bytes(2)
    except KeyError:
        raise KeyError(f"Invalid QTYPE: {qtype}")


def get_qclass_encoded(qclass: str) -> bytes:
    try:
        return QCLASS_MAPPING[qclass].to_bytes(2)
    except KeyError:
        raise KeyError(f"Invalid QCLASS: {qclass}")


class ResponseParser:
    def __init__(self, response: bytes):
        self.response = response

        self.headers = OrderedDict()
        self.raw_headers = b""

        self.ptr = 12

        self.question_section = []
        self.raw_question_section = b""
        self.answer_section = []
        self.raw_answer_section = b""
        self.authority_section = []
        self.raw_authority_section = b""
        self.additional_section = []
        self.raw_additional_section = b""

        self.parse_headers()
        self.parse_question_section()
        self.parse_answer_section()
        # self.parse_authority_section()
        # self.parse_additional_section()

    def parse_headers(self):
        self.raw_headers = self.response[:12]
        hb = self.raw_headers

        self.headers["ID"] = int.from_bytes(hb[:2])
        self.headers["QR"] = hb[2] & 0x10000000 >> 7
        self.headers["OPCODE"] = hb[2] & 0x01111000 >> 3
        self.headers["AA"] = hb[2] & 0x00000100 >> 2
        self.headers["TC"] = hb[2] & 0x00000010 >> 1
        self.headers["RD"] = hb[2] & 0x00000001
        self.headers["RA"] = hb[3] & 0x10000000 >> 7
        self.headers["Z"] = hb[3] & 0x01110000 >> 4
        self.headers["RCODE"] = hb[3] & 0x00001111
        self.headers["QDCOUNT"] = int.from_bytes(hb[4:6])
        self.headers["ANCOUNT"] = int.from_bytes(hb[6:8])
        self.headers["NSCOUNT"] = int.from_bytes(hb[8:10])
        self.headers["ARCOUNT"] = int.from_bytes(hb[10:12])

    def parse_question_section(self):
        last_index, qname_qtype_qclass = get_qname_qtype_qclass(
            self.response, self.ptr, self.headers["QDCOUNT"]
        )

        self.raw_question_section = self.response[self.ptr : last_index]

        self.ptr = last_index

        self.question_section += qname_qtype_qclass

    def parse_answer_section(self):
        last_index, resource_records = get_resource_records(
            self.response, self.ptr, self.headers["ANCOUNT"]
        )

        self.raw_answer_section = self.response[self.ptr : last_index]

        self.ptr = last_index

        self.answer_section += resource_records

    def parse_authority_section(self) -> dict:
        raise NotImplementedError

    def parse_additional_section(self) -> dict:
        raise NotImplementedError


def get_qname(b: bytes, ptr: int) -> tuple[int, bytes]:
    qname: list[bytes] = []
    while True:
        label_length = b[ptr]
        if label_length == 0:
            ptr += 1
            return ptr, b".".join(qname)
        elif label_length & 0b11000000 == 0b11000000:
            _, pointed_name = get_qname(
                b, (label_length & 0x00111111) << 8 | b[ptr + 1]
            )
            ptr += 2
            return ptr, b".".join((b".".join(qname), pointed_name))
        else:
            ptr += 1
            label = b[ptr : ptr + label_length]
            ptr += label_length
            qname.append(label)


def get_qname_qtype_qclass(
    b: bytes, ptr: int, ammount: int
) -> tuple[int, list[dict[str, bytes]]]:
    records = []
    for _i in range(0, ammount):
        ptr, qname = get_qname(b, ptr)
        records.append(
            {
                "qname": qname,
                "qtype": b[ptr : ptr + 2],
                "qclass": b[ptr + 2 : ptr + 4],
            }
        )
        ptr += 4

    return ptr, records


def get_resource_records(
    b: bytes, ptr: int, ammount: int
) -> tuple[int, list[dict[str, bytes]]]:
    resource_records = []
    for _i in range(0, ammount):
        record = {}

        ptr, name_type_class = get_qname_qtype_qclass(b, ptr, 1)

        record["name"] = name_type_class[0]["qname"]
        record["type"] = name_type_class[0]["qtype"]
        record["class"] = name_type_class[0]["qclass"]

        record["ttl"] = b[ptr : ptr + 4]
        ptr += 4

        record["rdlength"] = b[ptr : ptr + 2]
        rdlength = int.from_bytes(record["rdlength"])
        ptr += 2

        record["rdata"] = b[ptr : ptr + rdlength]
        ptr += rdlength

        resource_records.append(record)

    return ptr, resource_records
