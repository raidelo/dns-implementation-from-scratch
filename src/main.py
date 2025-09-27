from cli import parse_args
from comms import send_query
from low import ResponseParser
from parsing import parse_server_string


def main():
    args = parse_args()

    s = parse_server_string(args.server)

    if not s["status"]:
        print("error: {}".format(s["server"] or s["port"]))
        exit(1)

    response = send_query(
        (s["server"], s["port"]),
        args.domains,
        args.qtype,
        args.qclass,
        args.non_recursive,
    )

    print("Received:", response)

    response_parsed = ResponseParser(response)


if __name__ == "__main__":
    main()
