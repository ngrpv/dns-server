import json
import os.path
import socket
import struct
from typing import Literal

PORT = 53
HOST = ""
BUF_SIZE = 1024


def decode_labels(message, offset):
    labels = []

    while True:
        length, = struct.unpack_from("!B", message, offset)

        if (length & 0xC0) == 0xC0:
            pointer, = struct.unpack_from("!H", message, offset)
            offset += 2

            return labels + decode_labels(message, pointer & 0x3FFF)[0], offset

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

        question = {"domain_name": '.'.join(map(lambda x: x.decode(), qname)),
                    "query_type": qtype,
                    "query_class": qclass}

        questions.append(question)

    return questions, offset


def decode_msg_until_co(message, offset):
    labels = []
    flag = False
    start = offset
    while True:
        length, = struct.unpack_from("!B", message, offset)
        offset += 1
        if length == 0xC0:
            flag = True
            continue
        if length == 0x0C and flag:
            if len(labels) == 0:
                return b'', offset
            return struct.unpack_from("!%ds" % len(labels), message,
                                      start), offset
        flag = False
        labels.append(chr(length))


def parse_ip(data: bytes):
    ip = []
    for i in range(4):
        ip.append(int(data[i]))
    ''.join([str(i) for i in ip])


A_Format = struct.Struct('!4B')

DNS_ANS_EXTRA_FORMAT = struct.Struct('!IH')


def parse_data_with_pointer(message: bytes, offset: int):
    name_head = []
    while True:
        current_byte, = struct.unpack_from("!B", message, offset)
        if current_byte == 3:
            offset += 1
            continue
        if current_byte == 0xC0:
            offset += 1
            offset_to_name_tail, = struct.unpack_from("!B", message, offset)
            name, _ = decode_labels(message, offset_to_name_tail)
            if len(name_head) > 0:
                return [str.encode(''.join(name_head))] + name, offset + 1
            return name, offset + 1
        name_head.append(chr(current_byte))
        offset += 1


def decode_ns_type_data(message, offset, data_length):
    data, _ = parse_data_with_pointer(message, offset)
    offset += data_length
    return '.'.join(map(lambda x: x.decode(), data)), offset


def decode_a_type_data(message, offset, data_length):
    data = A_Format.unpack_from(message, offset)
    return '.'.join(map(str, data)), offset + data_length


def decode_ptr_data(message, offset, data_length):
    off = offset
    acc = []
    i = 0
    while True:
        current_byte, = struct.unpack_from("!c", message, offset)
        if current_byte == b'\x00' or offset >= off + data_length:
            return ''.join(acc), off + data_length
        if current_byte != b'\x03' and current_byte != b'\x05':
            if str.isprintable(current_byte.decode()):
                acc.append(current_byte.decode())
        else:
            acc.append('.')
        offset += 1


def decode_answers_section(message, offset, count, questions):
    answers = []
    for _ in range(count):
        name, offset = parse_data_with_pointer(message, offset)
        if name == b'':
            name = questions[0]['domain_name']
        atype, ans_class = DNS_QUERY_SECTION_FORMAT.unpack_from(message,
                                                                offset)
        offset += DNS_QUERY_SECTION_FORMAT.size
        ttl, data_length = DNS_ANS_EXTRA_FORMAT.unpack_from(message, offset)
        offset += DNS_ANS_EXTRA_FORMAT.size
        data = []
        if atype == 2:
            data, offset = decode_ns_type_data(message, offset, data_length)
        if atype == 1:
            data, offset = decode_a_type_data(message, offset, data_length)
        if atype == 12:
            data, offset = decode_ptr_data(message, offset, data_length)
        answer = {
            "answer_name": '.'.join(map(lambda x: x.decode(), name)),
            "answer_type": atype,
            "answer_class": ans_class,
            "ttl": ttl,
            "data": data
        }
        answers.append(answer)
    return answers, offset


DNS_QUERY_MESSAGE_HEADER = struct.Struct("!6H")


def decode_dns_message(message):
    id, flags, questions_count, answers_count, num_of_authority_RR, num_of_additional_RRs = DNS_QUERY_MESSAGE_HEADER.unpack_from(
        message)

    qr = (flags & 0x8000) != 0
    opcode = (flags & 0x7800) >> 11
    aa = (flags & 0x0400) != 0
    tc = (flags & 0x200) != 0
    rd = (flags & 0x100) != 0
    ra = (flags & 0x80) != 0
    z = (flags & 0x70) >> 4
    rcode = flags & 0xF

    offset = DNS_QUERY_MESSAGE_HEADER.size
    questions, offset = decode_question_section(message, offset,
                                                questions_count)
    answers, offset = decode_answers_section(message, offset, answers_count,
                                             questions)

    result = {"id": id,
              "is_response": qr,
              "opcode": opcode,
              "is_authoritative": aa,
              "is_truncated": tc,
              "recursion_desired": rd,
              "recursion_available": ra,
              "reserved": z,
              "response_code": rcode,
              "question_count": questions_count,
              "answer_count": answers_count,
              "authority_count": num_of_authority_RR,
              "additional_count": num_of_additional_RRs,
              "questions": questions,
              "answers": answers}

    return result


def get_dns_data(request, ip):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(1)
        sock.sendto(request, (ip, 53))
        try:
            ans, server = sock.recvfrom(1024)
        except socket.timeout:
            return
        return ans


class Cache:
    @classmethod
    def init_from(cls, filename, dns_ip):
        if os.path.isfile(filename):
            with open(filename, 'r') as f:
                cache = cls(json.loads(f.read()))
                return cache
        else:
            return Cache(filename, dns_ip)

    def __init__(self, filename, dns_ip):
        self.filename = filename
        self.ns_cache = {}
        self.dns_ip = dns_ip

    def get(self, type: Literal['ns', 'ptr', 'a'], question: dict,
            response: bytes) -> bytes or None:
        if type == 'ns':
            if not question['domain_name'] in self.ns_cache:
                reply = get_dns_data(response, self.dns_ip)
                if not reply:
                    return
                decoded_reply = decode_dns_message(reply)
                for ans in decoded_reply['answers']:
                    if ans['ttl'] > 0:
                        self.ns_cache[ans['answer_name']] = self.ns_cache[
                            'data']
                        #         self.ns_cache[]
    #   if type == ''


def launch_sever():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, PORT))
        while True:
            data, addr = sock.recvfrom(BUF_SIZE)
            print(decode_dns_message(data))

            print('request:' + str(decode_dns_message(data)))
            print()
            result = get_dns_data(data, "10.98.240.10")
            if result is None:
                print("Dns time out")
                continue
            sock.sendto(result, addr)
            print('reply: ' + json.dumps(decode_dns_message(result), indent=4,
                                         default=str))


if __name__ == '__main__':
    launch_sever()
