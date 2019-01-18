import threading, socket, dnslib
from search import search


class UDPHandler():
    """
    Class to handle UDP DNS requests.
    """

    def __init__(self):
        """
        Constructor for the UDP Handler class.
        """
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", 53))
        self.clients_list = []


    def respond_to_client(self, datagram, ip):
        """
        Respond result to client through UDP socket.
        :param datagram: Incoming UDP datagram.
        :param ip: Source IP address of datagram.
        """
        request = dnslib.DNSRecord.parse(datagram)
        recursion_desired = request.header.rd
        id = request.header.id
        answer, authority, additional, aa, rcode = [], [], [], 0, 0
        for question in request.questions:
            domain = question.qname.idna()
            rr_set, auth_set, addi_set = search(domain, question.qtype)
            answer += rr_set
            authority += auth_set
            additional += addi_set
            additional += request.ar
        if authority != []:
            aa = 1 # Mark as authorative answer.
        elif answer == [] and authority == []:
            rcode = 5 # Refuse unknown domains.
        # Build the response.
        response = dnslib.DNSRecord(dnslib.DNSHeader(id = id, qr = 1, aa = aa, ra = 0, rd = recursion_desired, rcode=rcode),
                                    questions = request.questions,
                                    rr   = answer,
                                    auth = authority,
                                    ar   = additional)
        # Write to the socket.
        self.sock.sendto(response.pack(), ip)


    def listen(self):
        """
        Listen for incoming UDP datagrams.
        Spawns new threads for each DNS request.
        """
        while True:
            question, client = self.sock.recvfrom(1024)
            t = threading.Thread(target=self.respond_to_client, args=(question, client,))
            t.start()


if __name__ == '__main__':
    # Make sure all log messages show up
    handler = UDPHandler()
    handler.listen()