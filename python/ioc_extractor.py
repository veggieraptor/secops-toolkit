import argparse
import re
from ipaddress import AddressValueError, ip_address

__version__ = "0.1.0"

PSEUDO_IP_PATTERN = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
#DOMAIN_PATTERN = r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,11}"
#URL_PATTERN = r"(?:https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/){1}[a-zA-Z0-9]{2,}(?:\.[a-zA-Z0-9\-]{2,})(?:\.[a-zA-Z0-9]{2,})?(?:\/[a-zA-Z0-9]*)*"

DOMAIN_PATTERN = r"(?:\w(?:[\w\-]{0,61}\w)?\.)+\w{2,11}"
URL_PATTERN = r"(?:https:\/\/www\.|http:\/\/www\.|https:\/\/|http:\/\/){1}\w{2,}(?:\.[\w\-]{2,})(?:\.\w{2,})?(?:\/\w*)*"

MD5_LEN = 32
SHA1_LEN = 40
SHA256_LEN = 64
SHA512_LEN = 128
HASH_PATTERN = rf"\b(?:[a-fA-F0-9]{{{MD5_LEN}}}|[a-fA-F0-9]{{{SHA1_LEN}}}|[a-fA-F0-9]{{{SHA256_LEN}}}|[a-fA-F0-9]{{{SHA512_LEN}}})\b"

def ioc_extractor(input_file, defang):
    with open (input_file, "r") as file:
        file_lines = file.read().splitlines()

    ipv4_addresses = set()
    domains = set()
    urls = set()
    hashes = set()
    for line in file_lines:
        pseudo_ip_addresses_found = re.findall(PSEUDO_IP_PATTERN, line)
        ipv4_addresses.update([addr for addr in pseudo_ip_addresses_found if is_valid_ipv4(addr)])

        urls_found = re.findall(URL_PATTERN, line)
        urls.update(urls_found)

        # I want to avoide to put urls in the domain list
        line_for_domains = line
        for url in urls_found:
            line_for_domains = line_for_domains.replace(url, " ")
        domains_found = re.findall(DOMAIN_PATTERN, line_for_domains)
        domains.update(domains_found)

        hashes_found = re.findall(HASH_PATTERN, line)
        hashes.update(hashes_found)

    print("# IOC SUMMARY")
    print(f"IPs: {len(ipv4_addresses)} | Domains: {len(domains)} | URLs: {len(urls)} | Hashes: {len(hashes)}")

    print("\n## IPs")
    if not ipv4_addresses:
        print("_None found_")
    else:
        for ip in sorted(ipv4_addresses):
            addr = defang_ip(ip) if defang else ip
            print(f"{addr:<24} {classify_ip(ip)}")

    print("\n## Domains")
    if not domains:
        print("_None found_")
    else:
        for domain in sorted(domains):
            non_ascii = find_non_ascii_char(domain)
            flag = f" [non ASCII char: {non_ascii}]" if non_ascii else ""
            printable_domain = defang_domain(domain) if defang else domain
            print(f"{printable_domain} {flag}")

    print("\n## URLs")
    if not urls:
        print("_None found_")
    else:
        for url in sorted(urls):
            non_ascii = find_non_ascii_char(url)
            flag = f" [non ASCII char: {non_ascii}]" if non_ascii else ""
            printable_url = defang_url(url) if defang else url
            print(f"{printable_url}{flag}")

    print("\n## Hashes")
    if not domains:
        print("_None found_")
    else:
        for hash in sorted(hashes):
            print(f"{classify_hash(hash):<7} {hash}")

def is_valid_ipv4(text):
    try:
        ip_address(text)
        return True
    except ValueError:
        return False

def classify_ip(text):
    addr = ip_address(text)
    if addr.is_loopback: return "loopback"
    if addr.is_multicast: return "multicast"
    if addr.is_reserved: return "reserved"
    if addr.is_link_local: return "link local"
    if addr.is_private: return "private"
    return "public"

def defang_ip(address):
    return  address.replace(".", "[.]")

def defang_domain(domain):
    return  domain.replace(".", "[.]")

def defang_url(url):
    url = url.replace("http","hxxp")
    url = url.replace("HTTP","HxxP")
    return  url.replace(".", "[.]")

def find_non_ascii_char(text):# -> list[str]: #Return non-ASCII character in text
    return [ch for ch in text if ord(ch) > 127]

def classify_hash(hash):
    length = len(hash)
    if length == MD5_LEN: return "MD5"
    if length == SHA1_LEN: return "SHA-1"
    if length == SHA256_LEN: return "SHA-256"
    if length == SHA512_LEN: return "SHA-512"
    return ""

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

