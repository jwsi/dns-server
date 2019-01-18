import threading, socket, dnslib, struct
from search import search


class TransportHandler():
    """
    Class to handle UDP DNS requests.
    """

    def __init__(self):
        """
        Constructor for the UDP Handler class.
        """
        self.udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.udp_sock.bind(("0.0.0.0", 53))
        self.tcp_sock.bind(("0.0.0.0", 53))
        self.tcp_sock.listen(5)
        self.clients_list = []

    def _edns_check(self, opt_record):
        """
        Checks request EDNS record for compliance with EDNS0.
        :param opt_record: OPT Record to check.
        :return: Whether the request is valid and a corresponding OPT RR.
        """
        flags = "do" if opt_record.edns_do else ""
        if opt_record.edns_ver != 0:
            opt = dnslib.EDNS0(version=0, ext_rcode=1, flags=flags, udp_len=opt_record.edns_len,)
            return False, opt
        return True, dnslib.EDNS0(version=0, ext_rcode=0, flags=flags, udp_len=opt_record.edns_len)

    def _build_response(self, data):
        """
        Builds the DNS response given binary data as a query.
        :param data: binary data in the form of a DNS query.
        :return: DNS response ready to be encoded into binary form.
        """
        request = dnslib.DNSRecord.parse(data)
        recursion_desired = request.header.rd
        id = request.header.id
        answer, authority, additional, aa, rcode, ok = [], [], [], 0, 0, True
        if request.ar != []:
            ok, opt = self._edns_check(request.ar[0])
            additional.append(opt)
        if ok:
            for question in request.questions:
                domain = question.qname.idna()
                rr_set, auth_set, addi_set = search(domain, question.qtype)
                answer += rr_set
                authority += auth_set
                additional += addi_set
            if authority != []:
                aa = 1  # Mark as authorative answer.
            elif answer == [] and authority == []:
                rcode = 5  # Refuse unknown domains.
        # Build the response.
        return dnslib.DNSRecord(dnslib.DNSHeader(id=id, qr=1, aa=aa, ra=0, rd=recursion_desired, rcode=rcode),
                                    questions=request.questions,
                                    rr=answer,
                                    auth=authority,
                                    ar=additional)

    def _send_response(self, response, protocol, connection=None, ip=None):
        """
        Send result to querying client through transport socket.
        :param protocol: Transport protocol in use.
        :param connection: TCP connection.
        :param response: response to send.
        :param ip: IP address of client.
        """
        # Write to the socket.
        if protocol == "udp":
            self.udp_sock.sendto(response.pack(), ip)
        else:
            # Pack the response with length for TCP transmission
            response = response.pack()
            length = struct.pack(">H", len(response))
            connection.sendall(length + response)
            connection.close()

    def respond(self, data, protocol, connection=None, ip=None):
        """
        Response handler function.
        :param data: incoming binary data to parse.
        :param protocol: request transport protocol.
        :param connection: optional TCP connection.
        :param ip: optional client IP address.
        """
        response = self._build_response(data)
        self._send_response(response, protocol, connection, ip)

    def udp_listen(self):
        """
        Listen for incoming UDP datagrams.
        Spawns new threads for each DNS request.
        """
        while True:
            data, client = self.udp_sock.recvfrom(8192)
            threading.Thread(target=self.respond, args=(data, "udp"),
                             kwargs={
                                 "ip" : client
                             }).start()

    def tcp_listen(self):
        """
        Listen for incoming TCP segments.
        Spawns new threads for each DNS request.
        """
        while True:
            connection, _ = self.tcp_sock.accept()
            data = connection.recv(8192).strip()
            length = struct.unpack(">H", data[:2])[0] # Extract and check length (first 2 bytes)
            if len(data[2:]) != length: # If length is incorrect then terminate
                connection.close()
                continue
            threading.Thread(target=self.respond, args=(data[2:], "tcp"),
                             kwargs={
                                 "connection" : connection
                             }).start()


if __name__ == '__main__':
    # Make sure all log messages show up
    handler = TransportHandler()
    threading.Thread(target=handler.udp_listen).start()
    threading.Thread(target=handler.tcp_listen).start()