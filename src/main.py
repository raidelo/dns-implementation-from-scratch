from cli import parse_args
from comms import send_request, parse_response
from low import create_request
from parsing import parse_server_string


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
