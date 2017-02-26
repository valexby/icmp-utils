# constants for spolksping package
import socket
import struct


ICMP_ECHO_REQUEST = 8, 0
ICMP_ECHO_REPLY = 0, 0
ICMP_TTL_EXCEEDED = 11, 0

MIN_PAYLOAD_SIZE = struct.calcsize("d")
