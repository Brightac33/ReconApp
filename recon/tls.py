import ssl
import socket
import datetime

def get_tls_info(domain: str) -> dict:
    context = ssl.create_default_context()
    context.check_hostname = False # We are just inspecting, not verifying strictly for connection
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
    
    # Set a timeout
    conn.settimeout(5.0)

    try:
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        
        # Parse dates
        not_before = cert.get('notBefore')
        not_after = cert.get('notAfter')
        
        # Simple date parsing
        # Format usually: 'Feb  5 14:13:19 2026 GMT'
        date_fmt = r'%b %d %H:%M:%S %Y %Z'
        
        valid_from = datetime.datetime.strptime(not_before, date_fmt) if not_before else None
        valid_to = datetime.datetime.strptime(not_after, date_fmt) if not_after else None
        
        now = datetime.datetime.utcnow()
        days_to_expire = (valid_to - now).days if valid_to else 0
        
        is_expired = days_to_expire < 0
        expiring_soon = 0 <= days_to_expire < 30

        subject = dict(x[0] for x in cert.get('subject', []))
        issuer = dict(x[0] for x in cert.get('issuer', []))
        
        return {
            "subject": subject,
            "issuer": issuer,
            "version": cert.get('version'),
            "serialNumber": cert.get('serialNumber'),
            "notBefore": not_before,
            "notAfter": not_after,
            "subjectAltName": cert.get('subjectAltName', []),
            "is_expired": is_expired,
            "expiring_soon": expiring_soon,
            "days_to_expire": days_to_expire
        }

    except Exception as e:
        return {"error": str(e)}
    finally:
        conn.close()
