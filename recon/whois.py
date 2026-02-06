import whois
import datetime

def get_whois_info(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        
        # Helper to handle dates which can be lists or single objects
        def format_date(d):
            if isinstance(d, list):
                return [x.isoformat() if hasattr(x, 'isoformat') else str(x) for x in d]
            if hasattr(d, 'isoformat'):
                return d.isoformat()
            return str(d) if d else None

        return {
            "registrar": w.registrar,
            "creation_date": format_date(w.creation_date),
            "updated_date": format_date(w.updated_date),
            "expiration_date": format_date(w.expiration_date),
            "name_servers": w.name_servers,
            "org": w.org,
            "country": w.country,
            "raw": w.text # Including raw text for the user to see if they want details
        }
    except Exception as e:
        return {"error": str(e)}
