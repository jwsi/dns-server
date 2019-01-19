# DNS Server 

![alt text](https://codebuild.eu-west-2.amazonaws.com/badges?uuid=eyJlbmNyeXB0ZWREYXRhIjoiallrNWZ2ZVNWSjBxVHZjcnd1TlBJTTlsbjYvYnNsSmd0c1FvN1cya3VMekRlRWpYUDZZSnNieG4xSktMREwvczRUMEthb2RJN3EwalFsOWpQdG10aWhrPSIsIml2UGFyYW1ldGVyU3BlYyI6IkptTHNRRjRHZStBcnhoSnkiLCJtYXRlcmlhbFNldFNlcmlhbCI6MX0%3D&branch=master "Build Status")

## Overview
- Authoritative non-recursive DNS server utilising AWS DynamoDB as a key-value record store.
- Fully EDNS compliant as per [DNS Flag Day](https://dnsflagday.net/).
- In use at [UH DNS](https://uh-dns.com/).
- Supports the following records:
  - **A** : IPv4 Address
  - **AAAA** : IPv6 Address
  - **CNAME** : Canonical Name
  - **NS** : Name Server
  - **SOA** : Source of Authority
  - **NAPTR** : Name Authority Pointer
  - **CAA** : Certification Authority Authorization
  - **ALIAS** : Hostname -> Dynamic(A or AAAA)
  - **TXT** : Text
  - **SRV** : Service Locator
  - **MX** : Mail Exchange
  
## Contributions
To contribute please raise an issue then open a pull request for review.



