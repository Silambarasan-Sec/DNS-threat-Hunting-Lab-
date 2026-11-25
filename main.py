
import dns.resolver
import dns.exception
import requests
import tldextract
import math
import json
import time

from collections import Counter, defaultdict
from scapy.all import PcapReader, DNS, IP, IPv6


# ==========================================
# Configuration
# ==========================================

resolver = dns.resolver.Resolver()
resolver.timeout = 3
resolver.lifetime = 5

extract_domain = tldextract.TLDExtract(
    suffix_list_urls=()
)


# ==========================================
# 1. Shannon Entropy
# ==========================================

def calculate_entropy(value):

    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) *
        math.log2(count / length)
        for count in counts.values()
    )


def entropy_analysis():

    domain = input("Enter domain: ").strip().lower()

    result = extract_domain(domain)
    label = result.domain

    entropy = calculate_entropy(label)

    print("\n--- Entropy Analysis ---")
    print("Domain:", domain)
    print("Analyzed label:", label)
    print("Length:", len(label))
    print("Unique characters:", len(set(label)))
    print(f"Entropy: {entropy:.2f}")


# ==========================================
# 2. DNS Lookup
# ==========================================

def dns_lookup(domain):

    try:

        answers = resolver.resolve(domain, "A")

        rrset = answers.rrset

        print("\n--- DNS Lookup ---")
        print("Domain:", domain)

        if rrset is not None:
            print("TTL:", rrset.ttl)

        for answer in answers:
            print("IP Address:", answer.to_text())

    except dns.resolver.NXDOMAIN:
        print("Domain does not exist")

    except dns.resolver.NoAnswer:
        print("No A record found")

    except dns.exception.DNSException as e:
        print("DNS error:", e)


# ==========================================
# 3. Extract DNS Records
# ==========================================

def dns_records(domain):

    records = {}

    record_types = [
        "A", "AAAA", "MX", "NS",
        "TXT", "SOA", "CNAME"
    ]

    for qtype in record_types:

        try:

            answers = resolver.resolve(domain, qtype)
            rrset = answers.rrset

            records[qtype] = {
                "ttl": rrset.ttl if rrset is not None else None,
                "values": [
                    answer.to_text()
                    for answer in answers
                ]
            }

        except dns.resolver.NXDOMAIN:
            records["status"] = "NXDOMAIN"
            break

        except dns.resolver.NoAnswer:
            records[qtype] = []

        except dns.exception.DNSException as e:
            records[qtype] = {
                "error": str(e)
            }

    return records


# ==========================================
# 4. NXDOMAIN and DGA Investigation
# ==========================================

def nxdomain_analysis(domains):

    total = 0
    nxdomain = 0
    errors = 0

    for domain in domains:

        try:

            resolver.resolve(domain, "A")
            total += 1

            print(domain, "NOERROR")

        except dns.resolver.NXDOMAIN:

            total += 1
            nxdomain += 1

            print(domain, "NXDOMAIN")

        except dns.resolver.NoAnswer:

            total += 1

            print(domain, "No A record")

        except dns.exception.DNSException:

            errors += 1

            print(domain, "DNS ERROR")

    print("\n--- NXDOMAIN Analysis ---")
    print("Conclusive queries:", total)
    print("NXDOMAIN:", nxdomain)
    print("Errors:", errors)

    if total == 0:
        print("No conclusive DNS responses")
        return

    ratio = nxdomain / total

    print(f"NXDOMAIN ratio: {ratio:.2%}")

    if ratio >= 0.5:
        print("[ALERT] High NXDOMAIN ratio")


# ==========================================
# 5. DNS Tunneling Detection
# ==========================================

def detect_dns_tunneling(queries):

    stats = defaultdict(lambda: {
        "total": 0,
        "subdomains": set(),
        "entropy_sum": 0.0,
        "long_labels": 0
    })

    for query in queries:

        query = query.lower().rstrip(".")

        result = extract_domain(query)

        if not result.domain or not result.suffix:
            continue

        parent = f"{result.domain}.{result.suffix}"

        subdomain = result.subdomain

        if not subdomain:
            continue

        data = stats[parent]

        data["total"] += 1

        data["subdomains"].add(subdomain)

        data["entropy_sum"] += calculate_entropy(
            subdomain
        )

        if max(map(len, subdomain.split("."))) >= 15:
            data["long_labels"] += 1

    print("\n--- DNS Tunneling Analysis ---")

    for domain, data in stats.items():

        total = data["total"]

        unique_ratio = len(data["subdomains"]) / total

        avg_entropy = data["entropy_sum"] / total

        print("\nDomain:", domain)
        print("Queries:", total)
        print(f"Unique ratio: {unique_ratio:.2%}")
        print(f"Average entropy: {avg_entropy:.2f}")
        print("Long labels:", data["long_labels"])

        if (
            total >= 4
            and unique_ratio >= 0.8
            and avg_entropy >= 3.5
            and data["long_labels"] >= 3
        ):

            print("[ALERT] Possible DNS tunneling")

        else:

            print("Threshold not exceeded")


# ==========================================
# 6. Fast Flux Investigation
# ==========================================

def fast_flux_analysis(domain, observations=5, delay=10):

    all_ips = set()
    previous_ips = set()
    ttl_values = []

    print("\n--- Fast Flux Analysis ---")

    for i in range(observations):

        try:

            answers = resolver.resolve(domain, "A")

            current_ips = {
                answer.to_text()
                for answer in answers
            }

            all_ips.update(current_ips)

            print(f"\nObservation {i + 1}")
            print("Current IPs:", current_ips)

            rrset = answers.rrset

            if rrset is not None:

                ttl_values.append(rrset.ttl)
                print("TTL:", rrset.ttl)

            if previous_ips:

                print(
                    "New IPs:",
                    current_ips - previous_ips
                )

                print(
                    "Removed IPs:",
                    previous_ips - current_ips
                )

            previous_ips = current_ips

        except dns.exception.DNSException as e:

            print("DNS error:", e)

        if i < observations - 1:
            time.sleep(delay)

    print("\n--- Results ---")
    print("Unique IP addresses:", len(all_ips))
    print("All IPs:", all_ips)

    if ttl_values:

        avg_ttl = sum(ttl_values) / len(ttl_values)

        print(f"Average TTL: {avg_ttl:.2f}")

        print("Assess IP rotation and infrastructure context.")


# ==========================================
# 7. CTI Enrichment
# ==========================================

def cti_enrichment(domain):

    domain = domain.lower().rstrip(".")

    result = extract_domain(domain)

    registered_domain = (
        f"{result.domain}.{result.suffix}"
        if result.suffix
        else domain
    )

    intelligence = {
        "domain": domain,
        "registered_domain": registered_domain,
        "entropy": calculate_entropy(result.domain),
        "dns_records": dns_records(domain),
        "registration": {}
    }

    # RDAP enrichment
    try:

        url = f"https://rdap.org/domain/{registered_domain}"

        response = requests.get(
            url,
            timeout=10
        )

        response.raise_for_status()

        data = response.json()

        intelligence["registration"] = {
            "name": data.get("ldhName"),
            "status": data.get("status"),
            "events": data.get("events"),
            "nameservers": data.get("nameservers")
        }

    except (requests.RequestException, ValueError) as e:

        intelligence["registration"] = {
            "error": str(e)
        }

    print(json.dumps(intelligence, indent=4))

    with open(
        "cti_results.json",
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            intelligence,
            file,
            indent=4
        )

    print("\nResults saved to cti_results.json")

    return intelligence


# ==========================================
# 8. PCAP Analysis
# ==========================================

def pcap_analysis(filename):

    domain_counts = Counter()
    client_queries = Counter()
    client_responses = Counter()
    client_nxdomain = Counter()

    try:

        with PcapReader(filename) as packets:

            for packet in packets:

                if not packet.haslayer(DNS):
                    continue

                if packet.haslayer(IP):

                    source = packet[IP].src
                    destination = packet[IP].dst

                elif packet.haslayer(IPv6):

                    source = packet[IPv6].src
                    destination = packet[IPv6].dst

                else:
                    continue

                dns_layer = packet[DNS]

                if not dns_layer.qd:
                    continue

                question = dns_layer.qd[0]

                domain = question.qname.decode(
                    errors="replace"
                ).rstrip(".").lower()

                # DNS Query
                if dns_layer.qr == 0:

                    domain_counts[domain] += 1
                    client_queries[source] += 1

                    print("QUERY:", source, domain)

                # DNS Response
                elif dns_layer.qr == 1:

                    client_responses[destination] += 1

                    if dns_layer.rcode == 3:

                        client_nxdomain[destination] += 1

        print("\n--- Top Domains ---")

        for domain, count in domain_counts.most_common(10):

            print(domain, count)

        print("\n--- Client Statistics ---")

        for client, total in client_queries.items():

            failed = client_nxdomain[client]
            responses = client_responses[client]

            ratio = failed / responses if responses else 0

            print(
                client,
                "Queries:", total,
                "Responses:", responses,
                "NXDOMAIN:", failed,
                f"Ratio: {ratio:.2%}"
            )

    except FileNotFoundError:

        print("PCAP file not found:", filename)


# ==========================================
# Test Data
# ==========================================

test_domains = [
    "google.com",
    "example.com",
    "xk29jd.invalid",
    "mz82kp.invalid",
    "zp92kx.invalid"
]

test_queries = [
    "www.google.com",
    "mail.google.com",
    "www.example.com",
    "x7k29m8zp4a9b2c7d8e9.example.net",
    "p9w82k7m3z8a1b5c4d6.example.net",
    "q8m29k7z3p8d2e5f6g7.example.net",
    "z9p28k7m4x8b2c5d6e7.example.net"
]


# ==========================================
# Main Menu
# ==========================================

def main():

    while True:

        print("""
==========================================
       DNS THREAT INTELLIGENCE TOOL
==========================================

1. DNS Lookup
2. Extract DNS Records
3. NXDOMAIN / DGA Investigation
4. Shannon Entropy Analysis
5. DNS Tunneling Detection
6. Fast Flux Investigation
7. CTI Enrichment
8. PCAP Analysis
0. Exit

==========================================
""")

        choice = input("Select an option: ").strip()

        if choice == "1":

            domain = input("Enter domain: ").strip()
            dns_lookup(domain)

        elif choice == "2":

            domain = input("Enter domain: ").strip()
            results = dns_records(domain)

            print(json.dumps(results, indent=4))

        elif choice == "3":

            nxdomain_analysis(test_domains)

        elif choice == "4":

            entropy_analysis()

        elif choice == "5":

            detect_dns_tunneling(test_queries)

        elif choice == "6":

            domain = input("Enter domain: ").strip()
            fast_flux_analysis(domain)

        elif choice == "7":

            domain = input("Enter domain: ").strip()
            cti_enrichment(domain)

        elif choice == "8":

            filename = input("Enter PCAP filename: ").strip()
            pcap_analysis(filename)

        elif choice == "0":

            print("Exiting DNS Threat Intelligence Tool")
            break

        else:

            print("Invalid option. Try again.")

        input("\nPress Enter to continue...")


# ==========================================
# Program Entry Point
# ==========================================

if __name__ == "__main__":

    main()
