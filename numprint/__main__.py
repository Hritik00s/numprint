"""Console entry point: ``python -m numprint [N]``."""

import argparse

from .core import print_tables


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="numprint", description="Print a multiplication table."
    )
    parser.add_argument(
        "number", nargs="?", type=int, default=10,
        help="number to build the table for (default: 10)",
    )
    args = parser.parse_args(argv)
    print_tables(args.number)


if __name__ == "__main__":
    main()