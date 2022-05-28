from dns_query import DNSQuery
from typing import Dict
from dns_record import DNSRecord
import struct


class DNSMessage:

    def __init__(self):
        self.authority: Dict[DNSQuery, list[DNSRecord]] = {}
        self.answers: Dict[DNSQuery, list[DNSRecord]] = {}
        self.questions: list[DNSQuery] = []
        self.additonal_RR = None
        self.additional: Dict[DNSQuery, list[DNSRecord]] = {}
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
        for i in range(msg.answers_RR):
            query, offset = DNSQuery.parse_query(bytes, offset)
            record, offset = DNSRecord.parse_record(bytes, offset,
                                                    query.q_type == 2)
            if not query in msg.answers:
                msg.answers[query] = []
            msg.answers[query].append(record)
        for i in range(msg.authority_RR):
            query, offset = DNSQuery.parse_query(bytes, offset)
            record, offset = DNSRecord.parse_record(bytes, offset,
                                                    query.q_type == 2)
            if not query in msg.authority:
                msg.authority[query] = []
            msg.authority[query].append(record)
        for i in range(msg.additonal_RR):
            query, offset = DNSQuery.parse_query(bytes, offset)
            record, offset = DNSRecord.parse_record(bytes, offset,
                                                    query.q_type == 2)
            if not query in msg.additional:
                msg.additional[query] = []
            msg.additional[query].append(record)
        return msg

    def to_bytes(self):
        self.authority_RR = 0
        self.questions_RR = len(self.questions)
        for i in self.answers.values():
            self.answers_RR += len(i)
        for _, i in self.authority.items():
            self.authority_RR += len(i)
        for i in self.additional.values():
            self.additonal_RR += len(i)
        #    print('aaa', self.authority_RR)
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
        for question in self.additional.keys():
            q2 = DNSQuery()
            q2.q_type = 1
            q2.q_class = 1
            q2.url = question.url
            for a in self.additional[question]:
                bytes += question.to_bytes()
                bytes += a.to_bytes()
        return bytes
