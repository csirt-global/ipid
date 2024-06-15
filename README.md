
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

