#!/usr/bin/env python3

import pickle
import socket
import struct
import time
from typing import Dict


class DNSServer:

    def __init__(self, port, forwarder, cache_file):
        self.port = port
        self.forwarder = forwarder
        self.cache_file = cache_file
        try:
            with open(self.cache_file, 'rb') as f:
                self.cache = pickle.load(f)
        except Exception:
            self.cache: Dict[DNSQuery, list[DNSRecord]] = {}

    def start(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(('', self.port))
            s.settimeout(1)
            while True:
                try:
                    data, address = s.recvfrom(1024)
                    print('Received')
                    ans = self.__make_answer(data)
                    print(ans)
                    print(1)
                    s.sendto(ans, address)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(e)
                    continue

    def __make_answer(self, incoming_data) -> bytes:
        msg = DNSMessage.parse_message(incoming_data)
        for question in msg.questions:
            if not question in self.cache or self.cache[
                question][0].exp_time < int(time.time()):
                return self.__ask_forwarder(incoming_data)
            if question.q_type == 6:
                msg.authority[question] = self.cache[question]
                msg.authority_RR += len(self.cache)
            else:
                msg.answers[question] = self.cache[question]
                msg.answers_RR += len(self.cache)
            print('From cache')
        msg.flags = 0x8580
        return msg.to_bytes()

    def __ask_forwarder(self, bytes) -> bytes:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(1)
            s.connect(self.forwarder)
            s.send(bytes)
            data = s.recv(1024)
            decoded = DNSMessage.parse_message(data)
            self.cache.update(decoded.answers)
            return data

    def save_cache(self):
        with open(self.cache_file, 'wb') as f:
            pickle.dump(self.cache, f)


class DNSMessage:

    def __init__(self):
        self.authority = None
        self.answers: Dict[DNSQuery, list[DNSRecord]] = {}
        self.questions: list[DNSQuery] = []
        self.additonal_RR = None
        self.authority_RR = None
        self.answers_RR = None
        self.questions_RR = None
        self.flags = None
        self.id = None

    @staticmethod
    def parse_message(bytes) -> 'DNSMessage':
        msg = DNSMessage()
        (msg.id, msg.flags, msg.questions_RR,
         msg.answers_RR, msg.authority_RR, msg.additonal_RR
         ) = struct.unpack_from('!HHHHHH', bytes, 0)
        msg.questions = []
        msg.answers = {}
        msg.authority = {}
        offset = 12
        for i in range(msg.questions_RR):
            query, offset = DNSQuery.parse_query(bytes, offset)
            msg.questions.append(query)
        for i in range(msg.answers_RR + msg.authority_RR + msg.additonal_RR):
            query, offset = DNSQuery.parse_query(bytes, offset)
            record, offset = DNSRecord.parse_record(bytes, offset,
                                                    query.q_type == 2)
            if not query in msg.answers:
                msg.answers[query] = []
            msg.answers[query].append(record)
        return msg

    def to_bytes(self):
        self.questions_RR = len(self.questions)
        for i in self.answers.values():
            self.answers_RR += len(i)
        bytes = struct.pack('!HHHHHH',
                            self.id,
                            self.flags,
                            self.questions_RR,
                            self.answers_RR,
                            self.authority_RR,
                            self.additonal_RR
                            )
        for question in self.questions:
            bytes += question.to_bytes()
        for question in self.answers.keys():
            for a in self.answers[question]:
                bytes += question.to_bytes()
                bytes += a.to_bytes()
        for question in self.authority.keys():
            for a in self.authority[question]:
                bytes += question.to_bytes()
                bytes += a.to_bytes()
        return bytes


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

    def __eq__(x, y):
        return x.url == y.url and x.q_type == y.q_type and x.q_class == y.q_class


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


def parse_short(bytes, offset):
    return (struct.unpack_from('!H', bytes, offset)[0], offset + 2)


def parse_long(bytes, offset):
    return (struct.unpack_from('!I', bytes, offset)[0], offset + 4)


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
    return (url, offset + 1)


def url_to_bytes(url):
    bytes = b''
    for part in url.split('.'):
        bytes += struct.pack('B', len(part))
        bytes += part.encode(encoding='utf-8')
    return bytes + b'\0'


if __name__ == '__main__':
    server = DNSServer(53, ('77.88.8.8', 53), 'cache')
    try:
        server.start()
    except KeyboardInterrupt:
        server.save_cache()
