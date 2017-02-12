#!/usr/bin/env python3
import logging
import argparse
import sys
from concurrent.futures import ProcessPoolExecutor

from myping.utils.ping import ping
import myping.constants as const


logging.basicConfig(
    level=logging.INFO,
    format='%(message)s')
LOG = logging.getLogger(__name__)


def _parse_args():
    parser = argparse.ArgumentParser(
        description='Simple pure python ping implementation')
    parser.add_argument('-c', '--count', type=int, default=4,
                        help='stop after sending COUNT echo requests')
    parser.add_argument('-t', '--timeout', type=float, default=2,
                        help='reply waiting timeout in seconds')
    parser.add_argument('-s', '--payload-size', type=int, default=56,
                        help='size of echo request payload')
    parser.add_argument('destination', nargs='+')
    args = parser.parse_args()

    if args.count <= 0:
        print(f'COUNT must be positive!')
        sys.exit(0)
    if args.timeout <= 0:
        print(f'TIMEOUT must be positive!')
        sys.exit(0)
    if args.payload_size < const.MIN_PAYLOAD_SIZE:
        print(f'PAYLOAD_SIZE must be greater than {const.MIN_PAYLOAD_SIZE}!')
        sys.exit(0)

    return args


def ping_wrapper(args):
    ping(*args)


def main():
    args = _parse_args()
    options = [args.timeout, args.count, args.payload_size]
    if len(args.destination) > 1:
        options.append(True)
    params = [(dest, *options) for dest in args.destination]

    with ProcessPoolExecutor() as executor:
        executor.map(ping_wrapper, params)


if __name__ == '__main__':
    main()
