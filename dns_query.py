from parsers import *
class DNSQuery:

    def __init__(self):
        self.url = None
        self.q_type = None

    @staticmethod
    def parse_query(bytes, offset) -> ('DNSQuery', int):
        query = DNSQuery()
        query.url, offset = parse_url(bytes, offset)
        query.q_type, offset = parse_short(bytes, offset)
        query.q_class, offset = parse_short(bytes, offset)
        return (query, offset)

    def to_bytes(self):
        return url_to_bytes(self.url) + struct.pack('!HH', self.q_type,
                                                    self.q_class)

    def __hash__(self):
        return hash(self.url) ** hash(self.q_type) ** hash(self.q_class)

    def __eq__(self, other):
        return self.url == other.url and self.q_type == other.q_type and self.q_class == other.q_class