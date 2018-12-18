import boto3, os, logging, dnslib
from boto3.dynamodb.conditions import Key, Attr

# Set global logging level.
logging.basicConfig(level=logging.INFO)
# create logger with 'DNS Request'.
logger = logging.getLogger("DNS")
logger.setLevel(logging.INFO)

# Define DynamoDB interaction system.
dynamodb = boto3.resource('dynamodb',
                          aws_access_key_id=os.environ["AWS_ACCESS_ID"],
                          aws_secret_access_key=os.environ["AWS_ACCESS_KEY"],
                          region_name='eu-west-2')
# Define the records table.
records = dynamodb.Table('records')


def search(domain, q_type):
    """
    Given an IDNA domain string and a record type,
    it will find the corresponding value if it exists.
    :param domain: IDNA domain string.
    :param record_type: Record type (A, AAAA, etc...)
    :return: String representing record value or None.
    """
    logger.info("Request: " + domain + " " + dnslib.QTYPE[q_type])
    rr_list = []

    try:
        # Search the database for all live records on the domain
        results = records.query(
            KeyConditionExpression=Key('domain').eq(domain),
            FilterExpression=Attr('live').eq(True)
        )["Items"]
    except KeyError:
        results = []

    for record in results:
        rr_list += _identify_record(record, q_type)

    logger.info("Response: " + str(rr_list))
    return rr_list


def _identify_record(record, q_type):
    rr_list = _cname_search(record) # CNAME record search (return for all records)
    if q_type == dnslib.QTYPE.A or q_type == dnslib.QTYPE.ANY:
        rr_list += _a_search(record) # A record search
    if q_type == dnslib.QTYPE.AAAA or q_type == dnslib.QTYPE.ANY:
        rr_list += _aaaa_search(record) # AAAA record search
    if q_type == dnslib.QTYPE.NS or q_type == dnslib.QTYPE.ANY:
        rr_list += _ns_search(record) # NS record search
    if q_type == dnslib.QTYPE.MX or q_type == dnslib.QTYPE.ANY:
        rr_list += _mx_search(record) # MX record search
    if q_type == dnslib.QTYPE.SOA or q_type == dnslib.QTYPE.ANY:
        rr_list += _soa_search(record) # SOA record search
    if q_type == dnslib.QTYPE.TXT or q_type == dnslib.QTYPE.ANY:
        rr_list += _txt_search(record) # TXT record search
    if q_type == dnslib.QTYPE.SRV or q_type == dnslib.QTYPE.ANY:
        rr_list += _srv_search(record) # SRV record search
    if q_type == dnslib.QTYPE.CAA or q_type == dnslib.QTYPE.ANY:
        rr_list += _caa_search(record) # CAA record search
    if q_type == dnslib.QTYPE.NAPTR or q_type == dnslib.QTYPE.ANY:
        rr_list += _naptr_search(record) # NAPTR record search
    return rr_list


def _a_search(record):
    """
    Searches and returns a list of A records for the domain.
    :param record: Overall record for domain
    :return: List of A records for the domain.
    """
    try:
        a_record = record["A"]
        a_list = []
        ttl = int(a_record["ttl"])
        for ip in a_record["value"]:
            a_list.append(dnslib.RR(rname = record["domain"],
                                    rtype = dnslib.QTYPE.A,
                                    rdata = dnslib.A(ip),
                                    ttl   = ttl))
        return a_list
    except KeyError:
        return []


def _aaaa_search(record):
    """
    Searches and returns a list of AAAA records for the domain.
    :param record: Overall record for domain
    :return: List of AAAA records for the domain.
    """
    try:
        aaaa_record = record["AAAA"]
        aaaa_list = []
        ttl = int(aaaa_record["ttl"])
        for ip in aaaa_record["value"]:
            aaaa_list.append(dnslib.RR(rname = record["domain"],
                                       rtype = dnslib.QTYPE.AAAA,
                                       rdata = dnslib.AAAA(ip),
                                       ttl   = ttl))
        return aaaa_list
    except KeyError:
        return []


def _cname_search(record):
    """
    Searches and returns a list of CNAME records for the domain.
    :param record: Overall record for domain
    :return: List of CNAME records for the domain.
    """
    try:
        cname_record = record["CNAME"]
        cname_list = []
        ttl = int(cname_record["ttl"])
        cname_list.append(dnslib.RR(rname = record["domain"],
                                    rtype = dnslib.QTYPE.CNAME,
                                    rdata = dnslib.CNAME(label = cname_record["domain"]),
                                    ttl   = ttl))
        return cname_list
    except KeyError:
        return []


def _ns_search(record):
    """
    Searches and returns a list of NS records for the domain.
    :param record: Overall record for domain
    :return: List of NS records for the domain.
    """
    try:
        ns_record = record["NS"]
        ns_list = []
        ttl = int(ns_record["ttl"])
        for ns in ns_record["value"]:
            ns_list.append(dnslib.RR(rname = record["domain"],
                                     rtype = dnslib.QTYPE.NS,
                                     rdata = dnslib.NS(label = ns),
                                     ttl   = ttl))
        return ns_list
    except KeyError:
        return []


def _mx_search(record):
    """
    Searches and returns a list of MX records for the domain.
    :param record: Overall record for domain
    :return: List of MX records for the domain.
    """
    try:
        mx_record = record["MX"]
        mx_list = []
        ttl = int(mx_record["ttl"])
        for value in mx_record["value"]:
            mx_list.append(dnslib.RR(rname = record["domain"],
                                     rtype = dnslib.QTYPE.MX,
                                     rdata = dnslib.MX(label = value["domain"],
                                                       preference = int(value["preference"])),
                                     ttl   = ttl))
        return mx_list
    except KeyError:
        return []


def _soa_search(record):
    """
    Searches and returns a list of SOA records for the domain.
    :param record: Overall record for domain
    :return: List of SOA records for the domain.
    """
    try:
        soa_record = record["SOA"]
        soa_list = []
        ttl = int(soa_record["ttl"])
        times = soa_record["times"]
        times = list(map(lambda time: int(time), times))
        soa_list.append(dnslib.RR(rname = record["domain"],
                                  rtype = dnslib.QTYPE.SOA,
                                  rdata = dnslib.SOA(mname = soa_record["mname"],
                                                     rname = soa_record["rname"],
                                                     times = times),
                                  ttl   = ttl))
        return soa_list
    except KeyError:
        return []


def _txt_search(record):
    """
    Searches and returns a list of TXT records for the domain.
    :param record: Overall record for domain
    :return: List of TXT records for the domain.
    """
    try:
        txt_record = record["TXT"]
        txt_list = []
        ttl = int(txt_record["ttl"])
        for txt in txt_record["value"]:
            txt_list.append(dnslib.RR(rname = record["domain"],
                                      rtype = dnslib.QTYPE.TXT,
                                      rdata = dnslib.TXT(txt),
                                      ttl   = ttl))
        return txt_list
    except KeyError:
        return []


def _srv_search(record):
    """
    Searches and returns a list of SRV records for the domain.
    :param record: Overall record for domain
    :return: List of SRV records for the domain.
    """
    try:
        srv_record = record["SRV"]
        srv_list = []
        ttl = int(srv_record["ttl"])
        for value in srv_record["value"]:
            srv_list.append(dnslib.RR(rname = record["domain"],
                                      rtype = dnslib.QTYPE.SRV,
                                      rdata = dnslib.SRV(priority = int(value["priority"]),
                                                         weight   = int(value["weight"]),
                                                         port     = int(value["port"]),
                                                         target   = value["target"]),
                                      ttl   = ttl))
        return srv_list
    except KeyError:
        return []


def _caa_search(record):
    """
    Searches and returns a list of CAA records for the domain.
    :param record: Overall record for domain
    :return: List of CAA records for the domain.
    """
    try:
        caa_record = record["CAA"]
        caa_list = []
        ttl = int(caa_record["ttl"])
        for value in caa_record["value"]:
            caa_list.append(dnslib.RR(rname = record["domain"],
                                      rtype = dnslib.QTYPE.CAA,
                                      rdata = dnslib.CAA(flags = int(value["flags"]),
                                                         tag   = value["tag"],
                                                         value = value["value"]),
                                      ttl   = ttl))
        return caa_list
    except KeyError:
        return []


def _naptr_search(record):
    """
    Searches and returns a list of NAPTR records for the domain.
    :param record: Overall record for domain
    :return: List of NAPTR records for the domain.
    """
    try:
        naptr_record = record["NAPTR"]
        naptr_list = []
        ttl = int(naptr_record["ttl"])
        for value in naptr_record["value"]:
            naptr_list.append(dnslib.RR(rname = record["domain"],
                                        rtype = dnslib.QTYPE.NAPTR,
                                        rdata = dnslib.NAPTR(order       = int(value["order"]),
                                                             preference  = int(value["preference"]),
                                                             flags       = value["flags"].encode('utf-8'),
                                                             service     = value["service"].encode('utf-8'),
                                                             regexp      = (value.get("regexp") or "").encode('utf-8'),
                                                             replacement = value["replacement"]),
                                        ttl   = ttl))
        return naptr_list
    except KeyError:
        return []