import boto3, os, logging, dnslib
from boto3.dynamodb.conditions import Key, Attr

# Set global logging level.
logging.basicConfig(level=logging.INFO)
# create logger with 'DNS'.
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
    rr_list, auth_list, addi_list = [], [], []
    try:
        # Search the database for all live records on the domain
        record = records.query(
            KeyConditionExpression=Key('domain').eq(domain.lower()),
            FilterExpression=Attr('live').eq(True)
        )["Items"][0]
        rr_list, auth_list, addi_list = _identify_record(record, q_type)
    except (KeyError, IndexError):
        pass
    logger.info("Response: " + str(rr_list))
    return rr_list, auth_list, addi_list

def _identify_record(record, q_type):
    """
    Given a db record and a query type this system will convert the DB record
    into a DNS record if one exists.
    :param record: DB record to convert.
    :param q_type: DNS Query type.
    :return: Tuple of lists:
    rr_list = resource record list.
    auth_list = authorative list.
    addi_list = additional list.
    """
    rr_list, auth_list, addi_list = [], [], []
    _cname_search(record, rr_list, auth_list, addi_list) # CNAME record search (return for all records)
    if rr_list != []:
        return rr_list, auth_list, addi_list
    if q_type == dnslib.QTYPE.A or q_type == dnslib.QTYPE.ANY:
        _a_search(record, rr_list, auth_list, addi_list)
    if q_type == dnslib.QTYPE.AAAA or q_type == dnslib.QTYPE.ANY:
        _aaaa_search(record, rr_list, auth_list, addi_list) # AAAA record search
    if q_type == dnslib.QTYPE.NS or q_type == dnslib.QTYPE.ANY:
        _ns_search(record, rr_list, addi_list) # NS record search
    if q_type == dnslib.QTYPE.MX or q_type == dnslib.QTYPE.ANY:
        _mx_search(record, rr_list, auth_list, addi_list) # MX record search
    if q_type == dnslib.QTYPE.TXT or q_type == dnslib.QTYPE.ANY:
        _txt_search(record, rr_list, auth_list, addi_list) # TXT record search
    if q_type == dnslib.QTYPE.SRV or q_type == dnslib.QTYPE.ANY:
        _srv_search(record, rr_list, auth_list, addi_list) # SRV record search
    if q_type == dnslib.QTYPE.CAA or q_type == dnslib.QTYPE.ANY:
        _caa_search(record, rr_list, auth_list, addi_list) # CAA record search
    if q_type == dnslib.QTYPE.NAPTR or q_type == dnslib.QTYPE.ANY:
        _naptr_search(record, rr_list, auth_list, addi_list) # NAPTR record search
    if q_type == dnslib.QTYPE.SOA or q_type == dnslib.QTYPE.ANY:
        _soa_search(record, rr_list, auth_list, addi_list, authority=False) # SOA record search
    if rr_list == []:
        _soa_search(record, rr_list, auth_list, addi_list, authority=True)  # Add SOA record to auth section for missing queries on a known domain
    return rr_list, auth_list, addi_list

def _a_search(record, rr_list, auth_list, addi_list):
    """
    Searches and adds any A records for the domain.
    :param record: Overall record for domain
    :param rr_list: Current record list for the domain
    :param auth_list: Authority list for the domain
    :param addi_list: Additional list for the domain
    """
    try:
        a_record = record["A"]
        ttl = int(a_record["ttl"])
        for ip in a_record["value"]:
            rr_list.append(dnslib.RR(rname = record["domain"],
                                     rtype = dnslib.QTYPE.A,
                                     rdata = dnslib.A(ip),
                                     ttl   = ttl))
            _add_authority(record["domain"], auth_list)
            _add_additional(addi_list)
    except:
        pass

def _aaaa_search(record, rr_list, auth_list, addi_list):
    """
    Searches and adds any AAAA records for the domain.
    :param record: Overall record for domain
    :param rr_list: Current record list for the domain
    :param auth_list: Authority list for the domain
    :param addi_list: Additional list for the domain
    """
    try:
        aaaa_record = record["AAAA"]
        ttl = int(aaaa_record["ttl"])
        for ip in aaaa_record["value"]:
            rr_list.append(dnslib.RR(rname = record["domain"],
                                     rtype = dnslib.QTYPE.AAAA,
                                     rdata = dnslib.AAAA(ip),
                                     ttl   = ttl))
            _add_authority(record["domain"], auth_list)
            _add_additional(addi_list)
    except:
        pass

def _cname_search(record, rr_list, auth_list, addi_list):
    """
    Searches and adds any CNAME records for the domain.
    :param record: Overall record for domain
    :param rr_list: Current record list for the domain
    :param auth_list: Authority list for the domain
    :param addi_list: Additional list for the domain
    """
    try:
        cname_record = record["CNAME"]
        ttl = int(cname_record["ttl"])
        rr_list.append(dnslib.RR(rname = record["domain"],
                                 rtype = dnslib.QTYPE.CNAME,
                                 rdata = dnslib.CNAME(label = cname_record["domain"]),
                                 ttl   = ttl))
        _add_authority(record["domain"], auth_list)
        _add_additional(addi_list)
    except:
        pass

def _ns_search(record, rr_list, addi_list):
    """
    Searches and adds any NS records for the domain.
    :param record: Overall record for domain
    :param rr_list: Current record list for the domain
    :param addi_list: Additional list for the domain
    """
    try:
        ns_record = record["NS"]
        ttl = int(ns_record["ttl"])
        for ns in ns_record["value"]:
            rr_list.append(dnslib.RR(rname = record["domain"],
                                     rtype = dnslib.QTYPE.NS,
                                     rdata = dnslib.NS(label = ns),
                                     ttl   = ttl))
            _add_additional(addi_list)
    except:
        pass

def _mx_search(record, rr_list, auth_list, addi_list):
    """
    Searches and adds any MX records for the domain.
    :param record: Overall record for domain
    :param rr_list: Current record list for the domain
    :param auth_list: Authority list for the domain
    :param addi_list: Additional list for the domain
    """
    try:
        mx_record = record["MX"]
        ttl = int(mx_record["ttl"])
        for value in mx_record["value"]:
            rr_list.append(dnslib.RR(rname = record["domain"],
                                     rtype = dnslib.QTYPE.MX,
                                     rdata = dnslib.MX(label = value["domain"],
                                                       preference = int(value["preference"])),
                                     ttl   = ttl))
            _add_authority(record["domain"], auth_list)
            _add_additional(addi_list)
    except:
        pass

def _soa_search(record, rr_list, auth_list, addi_list, authority=False):
    """
    Searches and adds any SOA records for the domain.
    :param record: Overall record for domain
    :param rr_list: Current record list for the domain
    :param auth_list: Authority list for the domain
    :param addi_list: Additional list for the domain
    :param authority: Add record to authority list or answer list.
    """
    try:
        soa_record = record["SOA"]
        ttl = int(soa_record["ttl"])
        times = soa_record["times"]
        times = list(map(lambda time: int(time), times))
        rr = dnslib.RR(rname = record["domain"],
                                 rtype = dnslib.QTYPE.SOA,
                                 rdata = dnslib.SOA(mname = soa_record["mname"],
                                                    rname = soa_record["rname"],
                                                    times = times),
                                 ttl   = ttl)
        if authority:
            auth_list.append(rr)
        else:
            rr_list.append(rr)
            _add_authority(record["domain"], auth_list)
            _add_additional(addi_list)
    except:
        pass

def _txt_search(record, rr_list, auth_list, addi_list):
    """
    Searches and adds any TXT records for the domain.
    :param record: Overall record for domain
    :param rr_list: Current record list for the domain
    :param auth_list: Authority list for the domain
    :param addi_list: Additional list for the domain
    """
    try:
        txt_record = record["TXT"]
        ttl = int(txt_record["ttl"])
        for txt in txt_record["value"]:
            rr_list.append(dnslib.RR(rname = record["domain"],
                                     rtype = dnslib.QTYPE.TXT,
                                     rdata = dnslib.TXT(txt),
                                     ttl   = ttl))
            _add_authority(record["domain"], auth_list)
            _add_additional(addi_list)
    except:
        pass

def _srv_search(record, rr_list, auth_list, addi_list):
    """
    Searches and adds any SRV records for the domain.
    :param record: Overall record for domain
    :param rr_list: Current record list for the domain
    :param auth_list: Authority list for the domain
    :param addi_list: Additional list for the domain
    """
    try:
        srv_record = record["SRV"]
        ttl = int(srv_record["ttl"])
        for value in srv_record["value"]:
            rr_list.append(dnslib.RR(rname = record["domain"],
                                     rtype = dnslib.QTYPE.SRV,
                                     rdata = dnslib.SRV(priority = int(value["priority"]),
                                                        weight   = int(value["weight"]),
                                                        port     = int(value["port"]),
                                                        target   = value["target"]),
                                     ttl   = ttl))
            _add_authority(record["domain"], auth_list)
            _add_additional(addi_list)
    except:
        pass

def _caa_search(record, rr_list, auth_list, addi_list):
    """
    Searches and adds any CAA records for the domain.
    :param record: Overall record for domain
    :param rr_list: Current record list for the domain
    :param auth_list: Authority list for the domain
    :param addi_list: Additional list for the domain
    """
    try:
        caa_record = record["CAA"]
        ttl = int(caa_record["ttl"])
        for value in caa_record["value"]:
            rr_list.append(dnslib.RR(rname = record["domain"],
                                     rtype = dnslib.QTYPE.CAA,
                                     rdata = dnslib.CAA(flags = int(value["flags"]),
                                                        tag   = value["tag"],
                                                        value = value["value"]),
                                     ttl   = ttl))
            _add_authority(record["domain"], auth_list)
            _add_additional(addi_list)
    except:
        pass

def _naptr_search(record, rr_list, auth_list, addi_list):
    """
    Searches and returns a list of NAPTR records for the domain.
    :param record: Overall record for domain
    :param rr_list: Current record list for the domain
    :param auth_list: Authority list for the domain
    :param addi_list: Additional list for the domain
    """
    try:
        naptr_record = record["NAPTR"]
        ttl = int(naptr_record["ttl"])
        for value in naptr_record["value"]:
            rr_list.append(dnslib.RR(rname = record["domain"],
                                     rtype = dnslib.QTYPE.NAPTR,
                                     rdata = dnslib.NAPTR(order       = int(value["order"]),
                                                          preference  = int(value["preference"]),
                                                          flags       = value["flags"].encode('utf-8'),
                                                          service     = value["service"].encode('utf-8'),
                                                          regexp      = (value.get("regexp") or "").encode('utf-8'),
                                                          replacement = value["replacement"]),
                                     ttl   = ttl))
            _add_authority(record["domain"], auth_list)
            _add_additional(addi_list)
    except:
        pass

def _add_authority(domain, auth_list):
    """
    Given a domain and an authority set,
    this function will add the UH DNS nameservers to the set.
    :param domain: Domain to be authoritative over.
    :param auth_list: Auth set to add to.
    """
    auth_list.append(
        dnslib.RR(rname=domain,
                  rtype=dnslib.QTYPE.NS,
                  rdata=dnslib.NS("ns1.uh-dns.com"),
                  ttl=3600))
    auth_list.append(
        dnslib.RR(rname=domain,
                  rtype=dnslib.QTYPE.NS,
                  rdata=dnslib.NS("ns2.uh-dns.com"),
                  ttl=3600))

def _add_additional(addi_list):
    """
    Given a domain and an additional set,
    this function will add the A records for the UH DNS nameservers to the set.
    :param addi_list: Additional set to add to.
    """
    if addi_list == []:
        addi_list.append(
            dnslib.RR(rname="ns1.uh-dns.com.",
                      rtype=dnslib.QTYPE.A,
                      rdata=dnslib.A("18.130.161.247"),
                      ttl=3600))
        addi_list.append(
            dnslib.RR(rname="ns2.uh-dns.com.",
                      rtype=dnslib.QTYPE.A,
                      rdata=dnslib.A("18.130.86.161"),
                      ttl=3600))