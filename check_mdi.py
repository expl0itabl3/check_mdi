#!/usr/bin/env python3

"""
Python script to enumerate valid Microsoft 365 domains, retrieve tenant name, and check for an MDI instance.
Based on: https://github.com/thalpius/Microsoft-Defender-for-Identity-Check-Instance.
Usage: ./check_mdi.py -d <domain>
"""

import argparse
import dns.resolver
import xml.etree.ElementTree as ET
from urllib.request import urlopen, Request
import json


# Get domains
def get_domains(args):
    domain = args.domain
    json_out = {}

    # Create a valid HTTP request
    # Example from: https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-oxwsadisc/18fe58cd-3761-49da-9e47-84e7b4db36c2
    body = f"""<?xml version="1.0" encoding="utf-8"?>
    <soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages" 
        xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types" 
        xmlns:a="http://www.w3.org/2005/08/addressing" 
        xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" 
        xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
        <soap:Header>
            <a:RequestedServerVersion>Exchange2010</a:RequestedServerVersion>
            <a:MessageID>urn:uuid:6389558d-9e05-465e-ade9-aae14c4bcd10</a:MessageID>
            <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
            <a:To soap:mustUnderstand="1">https://autodiscover.byfcxu-dom.extest.microsoft.com/autodiscover/autodiscover.svc</a:To>
            <a:ReplyTo>
            <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
            </a:ReplyTo>
        </soap:Header>
        <soap:Body>
            <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
            <Request>
                <Domain>{domain}</Domain>
            </Request>
            </GetFederationInformationRequestMessage>
        </soap:Body>
    </soap:Envelope>"""

    # Including HTTP headers
    headers = {
        "Content-type": "text/xml; charset=utf-8",
        "User-agent": "AutodiscoverClient"
    }

    url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
    if args.gov: 
        url = "https://autodiscover-s.office365.us/autodiscover/autodiscover.svc"

    # Perform HTTP request
    try:
        httprequest = Request(
            url, headers=headers, data=body.encode())

        with urlopen(httprequest) as response:
            response = response.read().decode()
    except Exception:
        if args.json: 
            print(json.dumps({"error":"Unable to execute request. Wrong domain"},indent=1))
        else:
            print("[-] Unable to execute request. Wrong domain?")
        exit()

    # Parse XML response
    domains = []

    tree = ET.fromstring(response)
    for elem in tree.iter():
        if elem.tag == "{http://schemas.microsoft.com/exchange/2010/Autodiscover}Domain":
            domains.append(elem.text)

    if not args.json:
        print("\n[+] Domains found:")
        print(*domains, sep="\n")
    else: 
        json_out["domains"] = domains 

    # Get tenant name
    tenant = ""

    for domain in domains:
        if "onmicrosoft.com" in domain:
            tenant = domain.split(".")[0]
            
    if not args.json:
        print(f"\n[+] Tenant found: \n{tenant}")
    else: 
        json_out["tenant"] = tenant 

    # Call check_mdi() with tenant
    mdi_check = check_mdi(tenant)

    if args.json:
        if mdi_check: 
            json_out["mdi"] = True
        else: 
            json_out["mdi"] = False 
    else: 
        if mdi_check: 
            print(f"\n[+] An MDI instance was found for {tenant}!\n")
        else: 
            print(f"\n[-] No MDI instance was found for {tenant}\n")


    if args.json: 
        print(json.dumps(json_out, indent=2))



# Identify MDI usage
def check_mdi(tenant):

    tenant += ".atp.azure.com"

    # Check if MDI instance exists
    try:
        dns.resolver.resolve(tenant)
        return True
    except Exception:
        return False

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Enumerates valid Microsoft 365 domains, retrieves tenant name, and checks for MDI instance")
    parser.add_argument(
        "-d", "--domain", help="input domain name, example format: example.com", required=True)
    parser.add_argument(
        "-j", "--json", action="store_true", help="output in JSON format", required=False)
    parser.add_argument(
        "--gov", action="store_true", help="query government tenancy", required=False)
    args = parser.parse_args()
    get_domains(args)
