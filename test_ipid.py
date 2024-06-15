from ipid import identify_ip, id_sj

HAS_SEC_TXT=['195.186.210.170'] #IPs that have direct security.txt
HAS_SSL=['31.214.245.43'] #IPs that do not have sec txt but do have SSL certs with domains 
HAS_DNS=['31.214.245.49'] #IPs that do not have sec txt nor SSL certs but do have pdns with domains
HAS_NEARBY_SSL=['190.52.48.250'] #IPs that do not have sec txt nor direct SSL certs nor have pdns but do have neighbours with consistent ssl domains

def testSecTxt():
    for ip in HAS_SEC_TXT:
        print( len(identify_ip(ip))>0 )

def testSSL():
    for ip in HAS_SSL:
        print( len(identify_ip(ip))>0 )

def testDNS():
    for ip in HAS_DNS:
        print( len(identify_ip(ip))>0 )

def testNearbySSL():
    for ip in HAS_NEARBY_SSL:
        assert len(identify_ip(ip))>0

def testShodan():
    f=open('../cisco/gb.json')
    emails=id_sj(f.read())
    assert len(emails)>0
    f.close()


def runAllTests():
    # testSecTxt()
    # testSSL()
    # testDNS()
    testNearbySSL()
    testShodan()

runAllTests()