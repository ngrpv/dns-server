from dns_server import DNSServer
from settings import *

if __name__ == '__main__':
    server = DNSServer(PORT, (DEFAULT_DNS_IP, PORT), CACHE_FILE_NAME)
    try:
        server.start()
    except KeyboardInterrupt:
        server.save_cache()
