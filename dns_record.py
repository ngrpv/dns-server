from parsers import *
import time


class DNSRecord:

    @staticmethod
    def parse_record(bytes, offset, is_link=False):
        record = DNSRecord()
        ttl, offset = parse_long(bytes, offset)
        record.exp_time = int(time.time()) + ttl
        length, offset = parse_short(bytes, offset)
        if is_link:
            record.info = url_to_bytes(parse_url(bytes, offset)[0])
        else:
            record.info = bytes[offset: offset + length]
        return (record, offset + length)

    def to_bytes(self):
        return struct.pack('!IH', self.exp_time - int(time.time()),
                           len(self.info)) + self.info
