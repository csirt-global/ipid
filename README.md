# IPID

## Goals

This script is for fingerprinting servers to determine what vunerabilities should lead to responsible disclosure. 


## TO DO
0. security.txt = done (shodan)
1. Find a domain
- ssl subject or issuer domain (exclude common CAs)
- check other ports on same IP (shodan)
    - EHLO banner
    - web content
    - ssh banner
    - SNMP
- passive dns domain (dumpsterDNS, circl.lu etc)
- reverse dns domain (exclude answers that contain the ip address in reverse as prob just the ISP?)
- check BGP and repeat for other IPs in the subnet, find a pattern?

2. Look for security contact on the domain (or IP if 1 unsuccessful)
- security.txt
- scrape 80/443 links for security
- scrape for contact
- whois
- geoIP and pass to relevant CSIRT.Global chapter
- pass to local NCSC

3. Add setting.py

## Shodan Input

When you query shodan.io, it returns a banner. 
The minimum parameters you can find it seems based on their documentation should always be something like this: 

```json
{
    "data": "Moxa Nport Device
            Status: Authentication disabled
            Name: NP5232I_4728
            MAC: 00:90:e8:47:10:2d",
    "ip_str": "46.252.132.235",
    "port": 4800,
    "org": "SingTel Mobile",
    "location": {
        "country_code": "SG"
    }
}
```
See link to documentation here: https://help.shodan.io/the-basics/search-query-fundamentals