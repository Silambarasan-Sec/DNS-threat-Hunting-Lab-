import dns.resolver
import dns.exception

domain = "google.com"

try:
    answers = dns.resolver.resolve(domain, "A")

    for answer in answers:
        print("Domain", domain)
        print("iPaddre", answer.address)
        if answers.rrset is not None:
            print("ttl",answers.rrset.ttl)
except dns.resolver.NXDOMAIN:
    print("domain not found")
except dns.resolver.NoAnswer:
    print("no dns found record")
except dns.exception.DNSException as e:
    print("dns error",e)
