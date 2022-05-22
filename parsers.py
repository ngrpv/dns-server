import struct


def parse_short(bytes, offset):
    return struct.unpack_from('!H', bytes, offset)[0], offset + 2


def parse_long(bytes, offset):
    return struct.unpack_from('!I', bytes, offset)[0], offset + 4


def parse_url(bytes, offset, recursive=False):
    url = ''
    while bytes[offset] != 0 and bytes[offset] < 0x80:
        for i in range(1, bytes[offset] + 1):
            url += chr(bytes[offset + i])
        url += '.'
        offset += bytes[offset] + 1
    if bytes[offset] >= 0x80:
        end_offset = parse_short(bytes, offset)[0] & 0x1fff
        url += parse_url(bytes, end_offset, True)[0]
        offset += 1
    if not recursive:
        url = url[:-1]
    return url, offset + 1


def url_to_bytes(url):
    bytes = b''
    for part in url.split('.'):
        bytes += struct.pack('B', len(part))
        bytes += part.encode(encoding='utf-8')
    return bytes + b'\0'
