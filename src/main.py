from cli import parse_args
from parsing import parse_server_string
from low import create_request
from comms import parse_response, send_request


def main():
    args = parse_args()

    s = parse_server_string(args.server)

    if not s["status"]:
        print("error: {}".format(s["server"] or s["port"]))
        exit(1)

    data = create_request(args.domains, args.qtype)

    response = send_request(data, (s["server"], s["port"]))

    print("Received:", response)

    response_parsed = parse_response(response)


if __name__ == "__main__":
    main()
