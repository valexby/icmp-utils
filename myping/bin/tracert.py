#!/usr/bin/env python3
import logging
import argparse
import sys

from myping.utils.tracert import traceroute
import myping.constants as const


logging.basicConfig(
    level=logging.INFO,
    format='%(message)s')
LOG = logging.getLogger(__name__)


def _parse_args():
    parser = argparse.ArgumentParser(
        description='Simple pure python ICMP traceroute implementation')
    parser.add_argument('destination')
    parser.add_argument('-m', '--max-hops', type=int, default=30,
                        help='maximum number of hops (max ttl value) '
                             'traceroute will probe. The default is 30')
    parser.add_argument('-f', '--first-ttl', type=int, default=1,
                        help='Specifies with what TTL to start. Defaults to 1')
    parser.add_argument('-t', '--timeout', type=float, default=0.1,
                        help='Specifies timeout for each probe in seconds. '
                             'Defaults to 0.1')
    args = parser.parse_args()

    if args.max_hops < 1:
        LOG.error('MAX_HOPS must be positive!')
        sys.exit(0)
    if args.first_ttl < 1:
        LOG.error('FIRST_TTL must be positive!')
        sys.exit(0)
    if args.first_ttl <= 0:
        LOG.error('TIMEOUT must be positive!')
        sys.exit(0)

    return args


def main():
    args = _parse_args()
    traceroute(args.destination, args.first_ttl, args.max_hops, args.timeout)


if __name__ == '__main__':
    main()
