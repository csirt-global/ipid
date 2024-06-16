#!env python3
import requests
import json
import pypdns
import pypssl
import re
import ipaddress
from operator import itemgetter

import creds

DEBUG=True


def id_sj(shodanjson: str) -> str:
    '''Identify all IPs in a Shodan result JSON'''
    try: 
        j = json.loads(shodanjson)
        for row in j:
            ip=row['ipaddress']
            print(ip, identifyIP(ip))
            #TODO optimise based on the data shodan already provides

    except Exception as e:
        print(e)


def getSecurityTxt(host: str, port=443) -> str:
    """Use HTTPS to download the security.txt file from its well-known location on the host"""
    try:
        r = requests.get(f"https://{host}:{port}/.well-known/security.txt", verify=False, timeout=2)
        if r.status_code==200:
            return r.text
        else:
            return False
    except (requests.exceptions.ConnectTimeout, requests.exceptions.ReadTimeout, requests.exceptions.ConnectionError) as e:
        return False


def passiveDNS(ipstr: str) -> set[str]:
    """Use circl.lu to find passive DNS records for the given IP and return a set of unique domains"""
    pdns = pypdns.PyPDNS(basic_auth=(creds.username,creds.password))
    res = pdns.iter_query(ipstr)
    domains=set()
    for r in res:
        domains.add(r.rdata)
    return domains


def passiveSSL(ipstr: str) -> set[str]:
    """Use circl.lu to find SSL Certs for the given IP and return a set of unique domains found in the certs on that IP
    OR return the raw cert data for a CIDR range"""
    circl = pypssl.PyPSSL(basic_auth=(creds.username, creds.password))
    ssl= circl.query(ipstr)
    domains=set()
    if '/' not in ipstr or (':' not in ipstr and ipstr.endswith('/32')) or (':' in ipstr and ipstr.endswith('/128')): #1 IP
        if ipstr in ssl: 
            for s in ssl[ipstr]['subjects']:
                if '.' in ssl[ipstr]['subjects'][s]['values'][0]: # . implies a real FQDN, not an X400 address like an issuer has
                    # parse domains out. Not always as simple as 'CN=example.com' - could be 'C=US,CN=example.com/emailAddress=admin@msp.com'
                    s1=ssl[ipstr]['subjects'][s]['values'][0]
                    xs=s1.split(',')
                    for x in xs:
                        if x.startswith('CN='):
                            end=''
                            if '/' in x:
                                end=x.index('/')
                            domains.add(x[3:end]) #remove CN= from subject
                            if '/' in x and '@' in x[end:]:
                                y=x[end:]
                                at=y.index('@')
                                domains.add(y[at+1:])
        return domains
    
    else: # CIDR search
        return ssl


def getPrefix(ipstr: str)-> str:
    '''Finds the BGP Prefix/CIDR subnet that this IP is routed to'''
    url=f'https://stat.ripe.net/data/looking-glass/data.json?resource={ipstr}'
    r=requests.get(url)
    if r.status_code==200:
        j=r.json()
        return j['data']['rrcs'][00]['peers'][00]['prefix']
    else:
        return "Error/0" #return small slash so won't be fed to passiveSSL on L78


def identifyIP(ipstr: str) -> set[str]:
    '''Returns a set of emails you can use to contact an IP owner about security issues'''
    sec=getSecurityTxt(ipstr)
    if sec:
        return getEmailAddressesFromSecurityTxt(sec)

    domains=passiveSSL(ipstr)
    domains=domains.union(passiveDNS(ipstr))
    if not domains:
        # search for common domain in subnet starting with nearest IPs to target
        prefix=getPrefix(ipstr)
        prefixsize=int(prefix[prefix.index('/')+1:])
        #ensure this path is tested
        if DEBUG:
            prefixsize=24
            prefix=prefix[0:-3]+'/24'
        if ':' not in ipstr and prefixsize > 23 or ':' in ipstr and prefixsize > 48 : #IPv4 or IPv6 'small' blocks
            ssl=passiveSSL(prefix)
            # get a sorted list of IPs with certs so we can find nearest neighbour
            ipa=ipaddress.ip_address(ipstr)
            ips=[]
            for ip in ssl:
                ipb=ipaddress.ip_address(ip)
                ips.append([abs(int(ipa) - int(ipb)), ipb])
            ips.sort(key=itemgetter(0))
            # for ip in ips:


    emails=set()
    for d in domains:
        emails=emails.union(identifyDomain(d))
    return emails

def getEmailAddressesFromSecurityTxt(sectxt:str)->set[str]:
    if not sectxt:
        return set()
    lines = sectxt.split('\n')
    addresses=set()
    for line in lines:
        if line.startswith('Contact:') and 'mailto' in line:
            address=re.search('mailto:(.+@.+)$', line).group(1)
            addresses.add(address)
    if len(addresses)==0:
        raise Exception('Failed to find email addresses in security.txt. Dumping whole file:\n'+sectxt)
    return addresses


def identifyDomain(domain:str)->set[str]:
    '''Returns a set of emails you can use to contact a domain owner about security issues'''
    sec=getSecurityTxt(domain)
    if sec:
        return getEmailAddressesFromSecurityTxt(sec)
    # TODO else scrape website for security contacts
    return set()


