import os
import uuid
import json
import asyncio
from datetime import datetime
from typing import Optional
from fastapi import FastAPI, HTTPException, Request, BackgroundTasks
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, HttpUrl
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

load_dotenv()

from backend.scanners.web_scanner import WebScanner
from backend.scanners.api_scanner import APIScanner
from backend.reports.report_generator import ReportGenerator
from backend.utils.db import ScanDatabase

limiter = Limiter(key_func=get_remote_address)
app = FastAPI(title="SecureScanner AI", version="1.0.0")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="frontend/static"), name="static")
templates = Jinja2Templates(directory="frontend/templates")

db = ScanDatabase()
scan_status = {}


class ScanRequest(BaseModel):
    url: str
    scan_type: str = "web"  # web or api
    api_headers: Optional[dict] = None
    api_endpoints: Optional[list] = None


class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str


@app.get("/")
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/report/{scan_id}")
async def report_page(request: Request, scan_id: str):
    return templates.TemplateResponse("report.html", {"request": request, "scan_id": scan_id})


@app.post("/api/scan", response_model=ScanResponse)
@limiter.limit("10/minute")
async def start_scan(request: Request, scan_req: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid.uuid4())
    scan_status[scan_id] = {"status": "running", "progress": 0, "message": "Initializing scan..."}
    background_tasks.add_task(run_scan, scan_id, scan_req)
    return ScanResponse(scan_id=scan_id, status="started", message="Scan initiated successfully")


@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str):
    if scan_id not in scan_status:
        result = db.get_scan(scan_id)
        if result:
            return {"status": "completed", "progress": 100}
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_status[scan_id]


@app.get("/api/scan/{scan_id}/result")
async def get_scan_result(scan_id: str):
    result = db.get_scan(scan_id)
    if not result:
        raise HTTPException(status_code=404, detail="Scan result not found")
    return result


@app.get("/api/history")
async def get_history():
    return db.get_all_scans()


@app.get("/api/report/{scan_id}/pdf")
async def download_pdf(scan_id: str):
    pdf_path = f"reports/{scan_id}.pdf"
    if not os.path.exists(pdf_path):
        result = db.get_scan(scan_id)
        if not result:
            raise HTTPException(status_code=404, detail="Scan not found")
        generator = ReportGenerator()
        generator.generate_pdf(result, pdf_path)
    return FileResponse(pdf_path, media_type="application/pdf", filename=f"security-report-{scan_id[:8]}.pdf")


@app.delete("/api/history/{scan_id}")
async def delete_scan(scan_id: str):
    db.delete_scan(scan_id)
    return {"message": "Deleted successfully"}


async def run_scan(scan_id: str, scan_req: ScanRequest):
    try:
        scan_status[scan_id] = {"status": "running", "progress": 10, "message": "Connecting to target..."}

        if scan_req.scan_type == "api":
            scanner = APIScanner(scan_req.url, scan_req.api_headers, scan_req.api_endpoints)
        else:
            scanner = WebScanner(scan_req.url)

        scan_status[scan_id] = {"status": "running", "progress": 30, "message": "Running security checks..."}
        raw_findings = await scanner.scan()

        scan_status[scan_id] = {"status": "running", "progress": 70, "message": "Analyzing with AI..."}
        generator = ReportGenerator()
        report = await generator.build_report(scan_id, scan_req.url, scan_req.scan_type, raw_findings)

        scan_status[scan_id] = {"status": "running", "progress": 90, "message": "Generating PDF report..."}
        os.makedirs("reports", exist_ok=True)
        generator.generate_pdf(report, f"reports/{scan_id}.pdf")

        db.save_scan(scan_id, report)
        scan_status[scan_id] = {"status": "completed", "progress": 100, "message": "Scan complete!"}

    except Exception as e:
        scan_status[scan_id] = {"status": "failed", "progress": 0, "message": str(e)}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=os.getenv("APP_HOST", "0.0.0.0"), port=int(os.getenv("APP_PORT", 8000)), reload=True)
