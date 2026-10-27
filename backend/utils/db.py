import sqlite3
import json
import os
from datetime import datetime
from typing import Optional


class ScanDatabase:
    def __init__(self, db_path: str = "scans.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    scan_type TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    risk_level TEXT,
                    total_findings INTEGER,
                    report_json TEXT NOT NULL
                )
            """)
            conn.commit()

    def save_scan(self, scan_id: str, report: dict):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    report.get("url", ""),
                    report.get("scan_type", "web"),
                    report.get("timestamp", datetime.utcnow().isoformat()),
                    report.get("summary", {}).get("risk_level", "Unknown"),
                    report.get("summary", {}).get("total", 0),
                    json.dumps(report),
                )
            )
            conn.commit()

    def get_scan(self, scan_id: str) -> Optional[dict]:
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT report_json FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
            return json.loads(row[0]) if row else None

    def get_all_scans(self) -> list:
        with sqlite3.connect(self.db_path) as conn:
            rows = conn.execute(
                "SELECT scan_id, url, scan_type, timestamp, risk_level, total_findings "
                "FROM scans ORDER BY timestamp DESC LIMIT 50"
            ).fetchall()
            return [
                {
                    "scan_id": r[0], "url": r[1], "scan_type": r[2],
                    "timestamp": r[3], "risk_level": r[4], "total_findings": r[5]
                }
                for r in rows
            ]

    def delete_scan(self, scan_id: str):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.commit()
