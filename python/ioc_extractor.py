import argparse
import re
from collections import Counter
from ipaddress import AddressValueError, ip_address

__version__ = "0.0.1"

PSEUDO_IP_PATTERN = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
DOMAIN_PATTERN = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,6}"

def ioc_extractor(input_file, defang):
    with open (input_file, "r") as file:
        file_lines = file.read().splitlines()

    ipv4_addresses = set()
    domains = set()
    urls = set()
    hashes = ()
    for line in file_lines:
        pseudo_ip_addresses_found = re.findall(PSEUDO_IP_PATTERN, line)
        ipv4_addresses.update([addr for addr in pseudo_ip_addresses_found if is_valid_ipv4(addr)])

        domains_found = re.findall(DOMAIN_PATTERN, line)
        domains.update(domains_found)


    print("# IOC SUMMARY")

    print("\n## IPs")
    for ip in ipv4_addresses:
        addr = defang_ip(ip) if defang else ip
        print(f"{addr:<24} {classify_ip(ip)}")

    print("\n## URLs")
    for domain in domains:
        addr = defang_domain(domain) if defang else domain
        print(f"{domain}")

def is_valid_ipv4(text):
    try:
        ip_address(text)
        return True
    except ValueError:
        return False

def classify_ip(text):
    addr = ip_address(text)
    if addr.is_loopback:
        return "loopback"
    if addr.is_multicast:
        return "multicast"
    if addr.is_reserved:
        return "reserved"
    if addr.is_link_local:
        return "link local"
    if addr.is_private:
        return "private"
    return "public"

def defang_ip(address):
    return  address.replace(".", "[.]")

def defang_domain(domain):
    return  domain.replace(".", "[.]")

def main():
    parser = argparse.ArgumentParser(
        prog="ioc_extractor",
        description=(
            "Extract IOCs (IPs, domains, URLs, hashes) from a text or log file."
        ),
        epilog=(
            "Examples:\n"
            "  %(prog)s data/sample/sample_ioc.txt\n"
            "  %(prog)s data/sample/sample_ioc.txt --defang"
        ),
    )
    parser.add_argument(
        "input_file",
        help="Path to the file to analyze.",
    )
    parser.add_argument(
        "--defang",
        action="store_true",
        help="Enable defang mode.",
    )
    args = parser.parse_args()

    ioc_extractor(args.input_file, args.defang)

if __name__ == "__main__":
    main()

