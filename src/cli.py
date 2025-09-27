from argparse import ArgumentParser


def parse_args():
    parser = ArgumentParser()
    parser.add_argument("domains", nargs="+")
    parser.add_argument("-s", "--server", default="8.8.8.8:53", dest="server")
    parser.add_argument("-t", "--qtype", default="A", dest="qtype")
    parser.add_argument(
        "-n",
        "--non-recursive",
        action="store_true",
        default=False,
        dest="non_recursive",
    )
    return parser.parse_args()
