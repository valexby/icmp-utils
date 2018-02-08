import logging
import socket
from socket import AF_INET, SOCK_RAW, IPPROTO_ICMP
import os
import time
import select
import struct
from utils.ping import send_one_ping, parse_ping_packet
import constants as const


LOG = logging.getLogger(__name__)


def send_one_tracert(*args, **kwargs):
    return send_one_ping(*args, **kwargs)


def receive_one_tracert(sock, pid, timeout):
    time_left = timeout
    while time_left > 0:
        started_select = time.clock()
        readable, *_ = select.select([sock], [], [], time_left)
        ended_select = time.clock()
        time_left -= (ended_select - started_select)

        if len(readable) == 0:
            break

        packet, addr = sock.recvfrom(1024)

        ip_header, icmp_header, icmp_payload = parse_ping_packet(packet)
        if icmp_header.function == const.ICMP_TTL_EXCEEDED:
            try:
                ip_header, icmp_header, icmp_payload = parse_ping_packet(
                    icmp_payload)
                time_sent = struct.unpack(
                    "d", icmp_payload[:struct.calcsize("d")])[0]
                time_spent = (ended_select - time_sent) * 100000
            except struct.error:
                time_spent = None
            return (socket.getfqdn(addr[0]), addr[0], time_spent, False)
        if icmp_header.function == const.ICMP_ECHO_REPLY and pid == icmp_header.pid:
            time_sent = struct.unpack(
                "d", icmp_payload[:struct.calcsize("d")])[0]
            time_spent = (ended_select - time_sent) * 100000
            return (socket.getfqdn(addr[0]), addr[0], time_spent, True)
    raise TimeoutError(timeout)


def _traceroute(sock, dest_ip, timeout, payload_size):
    pid = os.getpid() & 0xFFFF
    source = None
    latency = []
    trace_end = False
    for seq_id in range(1, 4):
        try:
            send_one_tracert(sock, dest_ip, pid, seq_id, payload_size)
            *source, time_spent, trace_end = receive_one_tracert(
                sock, pid, timeout)
            if time_spent is not None:
                latency.append('%0.1f ms' % time_spent)
            else:
                latency.append('?')
        except TimeoutError as e:
            latency.append('*')
    return source, latency, trace_end


def traceroute(destination, first_ttl=1, max_hops=30, timeout=0.1):
    dest_addr = socket.gethostbyname(destination)
    payload_size = 60
    LOG.info('traceroute to %s (%s), %d hops max, %d byte packets',
             destination, dest_addr, max_hops, payload_size)

    for ttl in range(first_ttl, max_hops + 1):
        with socket.socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as sock:
            sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            source, latency, trace_end = _traceroute(
                sock, dest_addr, timeout, payload_size)
            if source is not None:
                LOG.info('%2d  %s (%s)  %s  %s  %s', ttl, *source, *latency)
            else:
                LOG.info('%2d  * * *', ttl)
            if trace_end:
                break
