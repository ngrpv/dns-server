import pickle
import socket
import time

from typing import Dict
from dns_message import DNSMessage
from dns_query import DNSQuery
from dns_record import DNSRecord


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
                    ans = self.__make_answer(data)
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
                if question.q_type == 2:
                    question2 = DNSQuery()
                    question2.q_type = 1
                    question2.q_class = question.q_class
                    question2.url = 'ns1.' + question.url
                    if not question in msg.additional:
                        msg.additional[question] = []
                    msg.additional[question] += self.cache.get(question2, [])
                    question2.q_type = 28
                    msg.additional[question] += self.cache.get(question2, [])
                msg.answers[question] = self.cache[question]
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
            self.cache.update(decoded.additional)
            self.cache.update(decoded.authority)
            return data

    def save_cache(self):
        with open(self.cache_file, 'wb') as f:
            pickle.dump(self.cache, f)
