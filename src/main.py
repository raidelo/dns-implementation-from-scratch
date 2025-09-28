from pprint import pprint

from cli import parse_args
from comms import send_request
from low import ResponseParser, create_request
from parsing import parse_server_string


def main():
    args = parse_args()

    s = parse_server_string(args.server)

    if not s["status"]:
        print("error: {}".format(s["server"] or s["port"]))
        exit(1)

    recursive = not args.non_recursive

    req = create_request(
        args.domains,
        args.qtype,
        args.qclass,
        recursive,
    )

    resp = send_request(req, (s["server"], s["port"]))

    # Query debugging
    req = ResponseParser(req)
    pprint(req.raw_headers)
    pprint(req.headers)
    pprint(req.raw_question_section)
    pprint(req.question_section)

    # Response debugging
    resp = ResponseParser(resp)
    pprint(resp.raw_headers)
    pprint(resp.headers)
    pprint(resp.raw_question_section)
    pprint(resp.question_section)
    pprint(resp.raw_answer_section)
    pprint(resp.answer_section)
    pprint(resp.raw_authority_section)
    pprint(resp.authority_section)
    pprint(resp.raw_additional_section)
    pprint(resp.additional_section)


if __name__ == "__main__":
    main()
