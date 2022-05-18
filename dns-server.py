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

        question = {"domain_name": qname,
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


A_Format = struct.Struct('')

DNS_ANS_EXTRA_FORMAT = struct.Struct('!IH')


def parse_answer_data(message: bytes, offset: int):
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
            return [str.encode(''.join(name_head))] + name, offset + 1
        name_head.append(chr(current_byte))
        offset += 1


def decode_answers_section(message, offset, count, questions):
    answers = []
    for _ in range(count):
        name, offset = parse_answer_data(message, offset)
        if name == b'':
            name = questions[0]['domain_name']
        atype, ans_class = DNS_QUERY_SECTION_FORMAT.unpack_from(message,
                                                                offset)
        offset += DNS_QUERY_SECTION_FORMAT.size
        ttl, data_length = DNS_ANS_EXTRA_FORMAT.unpack_from(message, offset)
        offset += DNS_ANS_EXTRA_FORMAT.size
        data, _ = parse_answer_data(message, offset)
        offset += data_length
        answer = {
            "answer_name": name,
            "answer_type": atype,
            "answer_class": ans_class,
            "ttl": ttl,
            "data": data}
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


def get_dns_data(request):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(request, ("10.98.240.10", 53))
        ans, server = sock.recvfrom(1024)
        return ans


def launch_sever():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((HOST, PORT))
        while True:
            data, addr = sock.recvfrom(BUF_SIZE)
            print(decode_dns_message(data))

            print('request:' + str(decode_dns_message(data)))
            print()
            result = get_dns_data(data)
            sock.sendto(result, addr)
            print('reply: ' + str(decode_dns_message(result)))


if __name__ == '__main__':
    launch_sever()
