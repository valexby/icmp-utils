#
# # ICMP header is type(8), code(8), checksum(16), id(16), sequence(16)
# _IPv4Header = namedtuple('_IPv4Header', [
#     'version',
#     'ihl',
#     'tos',
#     'total_length',
#     'id',
#     'flags',
#     'fragment_offset',
#     'ttl',
#     'proto',
#     'checksum',
#     'src',
#     'dest',
# ])
#
#
# class IPv4Header(_IcmpHeader):
#     _format = 'BBHHHBBHII'
#
#     def pack(self):
#         return struct.pack(self._format, *self)
#
#     @classmethod
#     def unpack(cls, byte_obj):
#         byte1, tos, length,
#         return IcmpHeader(*struct.unpack(cls._format, byte_obj))
#
#     def __len__(self):
#         return struct.calcsize(self._format)


def get_ttl(ip_header):
    if not isinstance(ip_header, (bytes, bytearray)):
        raise TypeError('IP header must be bytes or bytearray object!')
    return ip_header[8]
