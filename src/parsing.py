import re

SERVER_ADDRESS = re.compile(
    r"^((\d{1,2}|1\d{2}|2[0-5]{2})\.){3}(\d{1,2}|1\d{2}|2[0-5]{2})$"
)
SERVER_PORT = re.compile(r"^(\d|[1-9]\d{1,3}|[1-5]\d{4}|6[1-5]{2}[1-3][1-5])$")

DEFAULT_REMOTE_PORT = 53


def parse_server_string(address: str) -> dict:
    address, _, port = address.partition(":")
    default = {"status": False, "server": None, "port": None}

    server_match = SERVER_ADDRESS.match(address)

    if not server_match:
        default["server"] = f"Invalid IPv4 format: {address}"
        return default
    else:
        default["server"] = server_match.group()

    if port:
        port_match = SERVER_PORT.match(port)
        if not port_match:
            default["server"] = None
            default["port"] = f"Invalid port: {port}"
            return default
        else:
            default["port"] = int(port_match.group())
    else:
        default["port"] = DEFAULT_REMOTE_PORT

    default["status"] = True

    return default
