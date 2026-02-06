import json
from fpdf import FPDF
import datetime

def generate_json(data: dict) -> str:
    return json.dumps(data, indent=4, default=str)

def generate_markdown(data: dict) -> str:
    md = f"# ReconApp Report: {data.get('domain')}\n"
    md += f"**Timestamp:** {data.get('timestamp')}\n"
    md += f"**Run ID:** {data.get('run_id')}\n\n"
    
    md += "## DNS Results\n"
    if "error" in data.get('dns', {}):
        md += f"Error: {data['dns']['error']}\n"
    else:
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            records = data['dns'].get(rtype, [])
            if records:
                md += f"### {rtype}\n"
                for r in records:
                    md += f"- {r}\n"
        
        md += f"\n**SPF Present:** {data['dns'].get('spf_present')}\n"
        md += f"**DMARC Present:** {data['dns'].get('dmarc_present')}\n"

    md += "\n## TLS Certificate\n"
    tls = data.get('tls', {})
    if "error" in tls:
        md += f"Error: {tls['error']}\n"
    else:
        md += f"- **Subject:** {tls.get('subject')}\n"
        md += f"- **Issuer:** {tls.get('issuer')}\n"
        md += f"- **Valid From:** {tls.get('notBefore')}\n"
        md += f"- **Valid To:** {tls.get('notAfter')}\n"
        md += f"- **Expiring Soon:** {tls.get('expiring_soon')}\n"

    md += "\n## WHOIS Info\n"
    whois = data.get('whois', {})
    if "error" in whois:
        md += f"Error: {whois['error']}\n"
    else:
        md += f"- **Registrar:** {whois.get('registrar')}\n"
        md += f"- **Creation Date:** {whois.get('creation_date')}\n"
        md += f"- **Expiration Date:** {whois.get('expiration_date')}\n"
        md += f"- **Organization:** {whois.get('org')}\n"
        md += f"- **Decorated Country:** {whois.get('country')}\n"

    return md

class PDF(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 15)
        self.cell(0, 10, 'ReconApp Scan Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', 0, 0, 'C')

def generate_pdf(data: dict, filename: str):
    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_font('Helvetica', '', 12)
    
    pdf.set_font('Helvetica', 'B', 12)
    pdf.cell(0, 10, f"Domain: {data.get('domain')}", 0, 1)
    pdf.cell(0, 10, f"Timestamp: {data.get('timestamp')}", 0, 1)
    pdf.cell(0, 10, f"Run ID: {data.get('run_id')}", 0, 1)
    pdf.ln(5)
    
    # DNS
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, "DNS Results", 0, 1)
    pdf.set_font('Courier', '', 10)
    
    if "error" in data.get('dns', {}):
        pdf.multi_cell(0, 5, f"Error: {data['dns']['error']}")
    else:
        dns_data = data['dns']
        for rtype in ["A", "AAAA", "MX", "NS", "TXT"]:
            records = dns_data.get(rtype, [])
            if records:
                pdf.set_font('Helvetica', 'B', 10)
                pdf.cell(0, 8, rtype, 0, 1)
                pdf.set_font('Courier', '', 9)
                for r in records:
                     # Clean text to avoid unicode errors in standard fpdf if not using unicode font
                    clean_r = r.encode('latin-1', 'replace').decode('latin-1')
                    pdf.multi_cell(0, 5, f"- {clean_r}")
        
        pdf.ln(2)
        pdf.set_font('Helvetica', '', 10)
        pdf.cell(0, 6, f"SPF Present: {dns_data.get('spf_present')}", 0, 1)
        pdf.cell(0, 6, f"DMARC Present: {dns_data.get('dmarc_present')}", 0, 1)

    pdf.ln(5)
    
    # TLS
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, "TLS Certificate", 0, 1)
    pdf.set_font('Helvetica', '', 10)
    
    tls = data.get('tls', {})
    if "error" in tls:
        pdf.multi_cell(0, 5, f"Error: {tls['error']}")
    else:
        # Helper to safely print dicts
        def safe(s): return str(s).encode('latin-1', 'replace').decode('latin-1')
        
        pdf.multi_cell(0, 5, f"Subject: {safe(tls.get('subject'))}")
        pdf.multi_cell(0, 5, f"Issuer: {safe(tls.get('issuer'))}")
        pdf.cell(0, 6, f"Valid From: {tls.get('notBefore')}", 0, 1)
        pdf.cell(0, 6, f"Valid To: {tls.get('notAfter')}", 0, 1)
        pdf.cell(0, 6, f"Expiring Soon: {tls.get('expiring_soon')}", 0, 1)

    pdf.ln(5)

    # WHOIS
    pdf.set_font('Helvetica', 'B', 14)
    pdf.cell(0, 10, "WHOIS Info", 0, 1)
    pdf.set_font('Helvetica', '', 10)
    
    whois = data.get('whois', {})
    if "error" in whois:
        pdf.multi_cell(0, 5, f"Error: {whois['error']}")
    else:
        def safe(s): return str(s).encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 5, f"Registrar: {safe(whois.get('registrar'))}")
        pdf.multi_cell(0, 5, f"Org: {safe(whois.get('org'))}")
        pdf.multi_cell(0, 5, f"Country: {safe(whois.get('country'))}")
        pdf.multi_cell(0, 5, f"Creation Date: {safe(whois.get('creation_date'))}")
    
    pdf.output(filename)
