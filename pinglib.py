#!/usr/bin/env python
import logging
import os
import socket
from socket import AF_INET, SOCK_RAW
import struct
import select
import time
from collections import namedtuple
import threading

import constants as const
from ip import get_ttl


LOG = logging.getLogger(__name__)
# fh = logging.FileHandler(threading.)


class TimeoutError(RuntimeError):
    def __init__(self, timeout):
        msg = f'Timeout within {timeout} sec'
        super().__init__(msg)


# ICMP header is type(8), code(8), checksum(16), id(16), sequence(16)
_IcmpHeader = namedtuple('_IcmpHeader', ['type', 'code', 'checksum', 'id', 'seq_num'])


class IcmpHeader(_IcmpHeader):
    _format = 'bbHHh'

    def pack(self):
        return struct.pack(self._format, *self)

    @classmethod
    def unpack(cls, byte_obj):
        return IcmpHeader(*struct.unpack(cls._format, byte_obj))

    def __len__(self):
        return struct.calcsize(self._format)


def get_icmp_checksum(dummy_header):
    def carry_around_add(a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)

    s = 0
    for i in range(0, len(dummy_header), 2):
        w = dummy_header[i] + (dummy_header[i+1] << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff


def send_one_ping(sock, dest_addr, identifier, seq_id, payload_size=56):
    """Send one ping to the given `dest_addr`."""
    if payload_size < const.MIN_PAYLOAD_SIZE:
        raise ValueError(f'Payload size must be greater than {const.MIN_PAYLOAD_SIZE}')

    dummy_header = IcmpHeader(*const.ICMP_ECHO_REQUEST, 0, identifier, seq_id)
    payload = struct.pack("d", time.clock()).ljust(payload_size, b'\x00')

    checksum = get_icmp_checksum(dummy_header.pack() + payload)
    header = IcmpHeader(*const.ICMP_ECHO_REQUEST, checksum, identifier, seq_id)
    data = header.pack() + payload

    sock.sendto(data, (dest_addr, 0))


def receive_one_ping(sock, identifier, timeout):
    """Receive ping from the socket."""
    time_left = timeout
    while time_left > 0:
        started_select = time.clock()
        readable, *_ = select.select([sock], [], [], time_left)
        ended_select = time.clock()
        time_left -= (ended_select - started_select)

        if len(readable) == 0:
            break

        packet, addr = sock.recvfrom(1024)

        header = IcmpHeader.unpack(packet[20:28])
        if (header.type, header.code) == const.ICMP_ECHO_REPLY and header.id == identifier:
            time_sent = struct.unpack("d", packet[28:28 + struct.calcsize("d")])[0]
            ip_payload_size = len(packet) - 20
            ttl = get_ttl(packet)
            time_spent = (ended_select - time_sent) * 100000
            return (ip_payload_size, socket.getfqdn(addr[0]), addr[0],
                    header.seq_num, ttl, time_spent)
    raise TimeoutError(timeout)


def _ping(dest_ip, timeout, seq_id, payload_size):
    """Returns either the delay (in seconds) or none on timeout."""
    identifier = os.getpid() & 0xFFFF
    with socket.socket(AF_INET, SOCK_RAW, const.ICMP_PROTO) as sock:
        send_one_ping(sock, dest_ip, identifier, seq_id, payload_size)
        ping_result = receive_one_ping(sock, identifier, timeout)
    return ping_result


def ping(hostname, timeout=2, count=4, payload_size=56, log_to_file=False):
    """Send `count` pings to `dest_addr` with the given `timeout` and display
    the result.
    """
    if log_to_file:
        fh = logging.FileHandler('%d-ping-%s.log' % (time.time(), hostname), 'w')
        LOG.addHandler(fh)
    try:
        dest_addr = socket.gethostbyname(socket.gethostbyname(hostname))
        frame_size = payload_size + 28
        LOG.info(f'PING {hostname} ({dest_addr}) {payload_size}({frame_size}) bytes of data.')

        for seq_id in range(1, count+1):
            try:
                ping_result = _ping(dest_addr, timeout, seq_id, payload_size)
                LOG.info("%d bytes from %s (%s): icmp_seq=%d ttl=%d time=%0.1f ms" % ping_result)
            except TimeoutError as e:
                LOG.info(e)
    except socket.gaierror as e:
        LOG.error(e)
    except PermissionError:
        LOG.error('Must be superuser')