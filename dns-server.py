#!/usr/bin/env python3

from dns_server import DNSServer

if __name__ == '__main__':
    server = DNSServer(53, ('216.239.32.10', 53), 'cache')
    try:
        server.start()
    except KeyboardInterrupt:
        server.save_cache()
