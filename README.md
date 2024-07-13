# IPID

## Goals

This script is for fingerprinting servers to find potential vunerabilities for responsible disclosure. 

## Requirements

Requirements are in the requirements.txt

```python

requests>2
pypdns>2
pypssl>2

```

## Quick Start

ADD HOW TO USE HERE

## Feature list

[x] security.txt (shodan)
[ ] Find a domain
[ ] ssl subject or issuer domain (exclude common CAs)
[ ] check other ports on same IP (shodan) 
    - [ ] EHLO banner
    - [ ] web content
    - [ ] ssh banner
    - [ ] SNMP
[ ] Passive dns domain (dumpsterDNS, circl.lu etc)
[ ] Reverse dns domain (exclude answers that contain the ip address in reverse as prob just the ISP?)
[ ] Check BGP and repeat for other IPs in the subnet, find a pattern?

2. Look for security contact on the domain (or IP if 1 unsuccessful)
[ ] security.txt
[ ] scrape 80/443 links for security
[ ] scrape for contact
[ ] whois
[ ] geoIP and pass to relevant CSIRT.Global chapter
[ ] pass to local NCSC

3. Add setting.py 
The goal here would be to decouple variables from the code logic as much as possible and improve configuration flexibility. 
It would be the one place to store all project relevant variables

## Shodan Input

### Shodan - Set up and configuration. 

You need credentials, information here: https://account.shodan.io/billing

username: the email 

When you query shodan.io, it returns a banner. 
See here about banners : https://help.shodan.io/the-basics/what-is-shodan

Banners vary greatly depending on the type of systems you are looking into. 
The simplest banner you could get as a result would look like this

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

## Expected Output

ADD EXPECTED OUTPUT HERE

## How to contribute

ADD HOW TO CONTRIBUTE HERE