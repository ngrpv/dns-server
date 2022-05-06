import socket
import struct

PORT = 53
HOST = ""
BUF_SIZE = 1024


# class Cache:
#     def __init__(self):
#         pass
#
#
# class DnsHeader:
#     header_struct = ''
#
#     def __init__(self):
#         self.identification = 0
#         self.number_of_questions = 0
#         self.identification = 0
#         pass
#
#     def set_flags(self, raw: bytes):
#         pass
#
#     @staticmethod
#     def parse(raw: bytes) -> 'DnsHeader':
#         header = DnsHeader()
#         header.identification = raw[:16]
#         header.set_flags(raw[16: 16 * 2])
#         header.number_of_questions = int.from_bytes(raw[16 * 2: 16 * 3], )
#         return header
#
#
# class DnsInfo:
#     def __init__(self):
#         self.identification = 0
#         pass
#
#     @staticmethod
#     def parse(data: bytes) -> 'DnsInfo':
#         info = DnsInfo()
#         header = data[0:4 * 16]
#         info.identification = header[:16]


def decode_labels(message, offset):
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF), offset

        if (length & 0xC0) != 0x00:
            raise AttributeError("unknown label encoding")

        offset += 1

        if length == 0:
            return labels, offset

        labels.append(*struct.unpack_from("!%ds" % length, message, offset))
        offset += length


DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")


def decode_question_section(message, offset, qdcount):
    questions = []

    for _ in range(qdcount):
        qname, offset = decode_labels(message, offset)

        qtype, qclass = DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
        offset += DNS_QUERY_SECTION_FORMAT.size

        question = {"domain_name": qname,
                    "query_type": qtype,
                    "query_class": qclass}

        questions.append(question)

    return questions, offset


DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")


def decode_dns_message(message):
    id, misc, qdcount, ancount, nscount, arcount = DNS_QUERY_MESSAGE_HEADER.unpack_from(
        message)

    qr = (misc & 0x8000) != 0
    opcode = (misc & 0x7800) >> 11
    aa = (misc & 0x0400) != 0
    tc = (misc & 0x200) != 0
    rd = (misc & 0x100) != 0
    ra = (misc & 0x80) != 0
    z = (misc & 0x70) >> 4
    rcode = misc & 0xF

    offset = DNS_QUERY_MESSAGE_HEADER.size
    questions, offset = decode_question_section(message, offset, qdcount)

    result = {"id": id,
              "is_response": qr,
              "opcode": opcode,
              "is_authoritative": aa,
              "is_truncated": tc,
              "recursion_desired": rd,
              "recursion_available": ra,
              "reserved": z,
              "response_code": rcode,
              "question_count": qdcount,
              "answer_count": ancount,
              "authority_count": nscount,
              "additional_count": arcount,
              "questions": questions}

    return result


def launch_sever():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, PORT))
        while True:
            data, conn = sock.recvfrom(BUF_SIZE)
            print(decode_dns_message(data))


if __name__ == '__main__':
    launch_sever()
