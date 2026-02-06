import dns.resolver
import dns.exception

def get_dns_info(domain: str) -> dict:
    results = {
        "A": [],
        "AAAA": [],
        "MX": [],
        "NS": [],
        "TXT": [],
        "spf_present": False,
        "dmarc_present": False
    }

    record_types = ["A", "AAAA", "MX", "NS", "TXT"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            for rdata in answers:
                results[rtype].append(rdata.to_text())
                
                # Check for SPF and DMARC in TXT records
                if rtype == "TXT":
                    txt_content = rdata.to_text()
                    if "v=spf1" in txt_content:
                        results["spf_present"] = True
                    if "v=DMARC1" in txt_content:
                        results["dmarc_present"] = True
                        
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout, dns.resolver.NoNameservers):
            continue
        except Exception as e:
            # Log error if needed, but for now just continue or store error
            results[f"{rtype}_error"] = str(e)

    # DMARC requires a specific lookup at _dmarc.domain
    try:
        dmarc_answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in dmarc_answers:
            results["TXT"].append(f"_dmarc: {rdata.to_text()}")
            if "v=DMARC1" in rdata.to_text():
                results["dmarc_present"] = True
    except:
        pass

    return results
