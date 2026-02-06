from fastapi import FastAPI, Request, Form, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import uvicorn
import datetime
import uuid
import json
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor
import os
import io

from recon import dns, tls, whois
from utils import report

app = FastAPI(title="ReconApp")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/scan", response_class=HTMLResponse)
async def scan(request: Request, domain: str = Form(...), ethics: str = Form(...)):
    if not ethics:
        raise HTTPException(status_code=400, detail="You must agree to the ethics statement.")
    
    # Basic validation
    domain = domain.strip().lower()
    if any(x in domain for x in ["http://", "https://", "/", " "]):
        return templates.TemplateResponse("index.html", {
            "request": request, 
            "error": "Invalid domain format. Please enter a domain name only (e.g. example.com)."
        })

    # Run modules in parallel
    run_id = str(uuid.uuid4())[:8]
    timestamp = datetime.datetime.now().isoformat()
    
    with ThreadPoolExecutor(max_workers=3) as executor:
        future_dns = executor.submit(dns.get_dns_info, domain)
        future_tls = executor.submit(tls.get_tls_info, domain)
        future_whois = executor.submit(whois.get_whois_info, domain)
        
        results = {
            "domain": domain,
            "run_id": run_id,
            "timestamp": timestamp,
            "dns": future_dns.result(),
            "tls": future_tls.result(),
            "whois": future_whois.result()
        }

    # JSON for the form (pass to template)
    data_json = json.dumps(results, default=str)

    return templates.TemplateResponse("results.html", {
        "request": request,
        "data": results,
        "data_json": data_json
    })

from starlette.background import BackgroundTask

# ... imports ...

@app.post("/export")
async def export(data: str = Form(...), format: str = Form(...)):
    try:
        results = json.loads(data)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid data")

    filename = f"recon_{results['domain']}_{results['run_id']}"
    
    if format == "json":
        return StreamingResponse(
            io.StringIO(report.generate_json(results)),
            media_type="application/json",
            headers={"Content-Disposition": f"attachment; filename={filename}.json"}
        )
    elif format == "md":
        return StreamingResponse(
            io.StringIO(report.generate_markdown(results)),
            media_type="text/markdown",
            headers={"Content-Disposition": f"attachment; filename={filename}.md"}
        )
    elif format == "pdf":
        temp_pdf = f"{filename}.pdf"
        report.generate_pdf(results, temp_pdf)
        
        # correct usage of BackgroundTask
        return FileResponse(
            temp_pdf, 
            media_type="application/pdf", 
            headers={"Content-Disposition": f"attachment; filename={filename}.pdf"},
            background=BackgroundTask(os.remove, temp_pdf)
        )
    else:
        raise HTTPException(status_code=400, detail="Invalid format")


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
