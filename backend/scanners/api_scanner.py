import asyncio
import json
import re
from urllib.parse import urlparse
from typing import Optional
import httpx


class APIScanner:
    def __init__(self, url: str, headers: Optional[dict] = None, endpoints: Optional[list] = None):
        self.base_url = url.rstrip("/") if url.startswith("http") else f"https://{url.rstrip('/')}"
        self.custom_headers = headers or {}
        self.extra_endpoints = endpoints or []
        self.findings = []
        self.client_config = {"timeout": 15, "follow_redirects": True, "verify": False}

    async def scan(self) -> list:
        async with httpx.AsyncClient(**self.client_config) as client:
            # First probe the base URL to understand the target
            self._base_status = await self._probe_base(client)
            tasks = [
                self._check_auth_bypass(client),
                self._check_rate_limiting(client),
                self._check_sensitive_endpoints(client),
                self._check_http_methods(client),
                self._check_injection_api(client),
                self._check_api_security_headers(client),
                self._check_graphql(client),
                self._check_swagger_exposure(client),
                self._check_bola(client),
                self._check_jwt_issues(client),
                self._check_mass_assignment(client),
                self._check_api_versioning(client),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    self.findings.extend(r)
        return self._deduplicate(self.findings)

    async def _probe_base(self, client) -> dict:
        try:
            r = await client.get(self.base_url, headers=self.custom_headers)
            return {"status": r.status_code, "body": r.text[:500], "headers": dict(r.headers)}
        except Exception:
            return {"status": 0, "body": "", "headers": {}}

    def _deduplicate(self, findings: list) -> list:
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("check"), f.get("url", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _is_auth_protected(self, status: int) -> bool:
        """Returns True if status indicates auth is required (not a false positive)."""
        return status in (401, 403)

    def _is_open(self, status: int) -> bool:
        return status in (200, 201, 202)

    # ── Auth Bypass ───────────────────────────────────────────────────────────
    async def _check_auth_bypass(self, client) -> list:
        findings = []
        bypass_headers = [
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
        ]
        protected_paths = ["/api/admin", "/admin", "/api/users/admin", "/api/management"]
        for path in protected_paths[:2]:
            url = self.base_url + path
            try:
                # Baseline: request without bypass header
                baseline = await client.get(url, headers=self.custom_headers)
                if self._is_open(baseline.status_code):
                    # Already open — not a bypass, skip
                    continue
                # Now try bypass headers
                for bh in bypass_headers:
                    r = await client.get(url, headers={**self.custom_headers, **bh})
                    if self._is_open(r.status_code) and r.status_code != baseline.status_code:
                        findings.append({
                            "check": "Authentication Bypass via HTTP Header",
                            "severity": "Critical", "category": "API2:2023",
                            "detail": f"Header '{list(bh.keys())[0]}' bypasses authentication on {path}.",
                            "evidence": f"Baseline: HTTP {baseline.status_code} → With {bh}: HTTP {r.status_code} at {url}",
                            "cve": None, "url": url,
                            "recommendation": "Never trust client-supplied headers for access control decisions."
                        })
                        break
            except Exception:
                pass
        return findings

    # ── Rate Limiting ─────────────────────────────────────────────────────────
    async def _check_rate_limiting(self, client) -> list:
        findings = []
        # Find a login-like endpoint
        candidates = ["/api/auth/login", "/api/login", "/auth/login",
                      "/api/v1/auth/login", "/login", "/api/token"]
        target_url = None
        for path in candidates:
            url = self.base_url + path
            try:
                r = await client.post(url, json={"username": "probe", "password": "probe"},
                                       headers=self.custom_headers)
                # 400/401/422 means endpoint exists and processes the request
                if r.status_code in (400, 401, 422, 200):
                    target_url = url
                    break
            except Exception:
                pass

        if not target_url:
            return findings

        try:
            tasks = [client.post(target_url,
                                  json={"username": "admin", "password": f"wrong{i}"},
                                  headers=self.custom_headers) for i in range(8)]
            responses = await asyncio.gather(*tasks, return_exceptions=True)
            valid = [r for r in responses if not isinstance(r, Exception)]
            status_codes = [r.status_code for r in valid]
            has_rate_limit = any(c in status_codes for c in [429, 423, 503])
            has_lockout = any("locked" in r.text.lower() or "too many" in r.text.lower()
                              for r in valid)
            if valid and not has_rate_limit and not has_lockout:
                findings.append({
                    "check": "API Login Endpoint Has No Rate Limiting",
                    "severity": "High", "category": "API4:2023",
                    "detail": "Login endpoint accepts unlimited rapid requests. Enables credential brute-force attacks.",
                    "evidence": f"8 rapid POST requests to {target_url} — status codes: {status_codes}, no 429 or lockout",
                    "cve": None, "url": target_url,
                    "recommendation": "Implement rate limiting (5 req/min per IP), exponential backoff, and account lockout."
                })
        except Exception:
            pass
        return findings

    # ── Sensitive Endpoints ───────────────────────────────────────────────────
    async def _check_sensitive_endpoints(self, client) -> list:
        findings = []
        # Each entry: (path, confirming_keywords, title, severity, detail)
        sensitive = [
            ("/api/config",       ["database", "secret", "password", "key", "host"],
             "API Config Endpoint Exposed", "Critical",
             "Configuration endpoint accessible without authentication. May expose secrets."),
            ("/api/env",          ["PATH=", "HOME=", "SECRET", "KEY", "PASSWORD"],
             "API Environment Variables Exposed", "Critical",
             "Environment variables endpoint accessible. Exposes secrets and system configuration."),
            ("/api/debug",        ["debug", "trace", "stack", "exception"],
             "API Debug Endpoint Exposed", "High",
             "Debug endpoint accessible. Reveals internal application state and stack traces."),
            ("/api/admin/users",  ["password", "role", "is_admin", "admin", "permission"],
             "Admin User List Exposed", "Critical",
             "Admin user listing accessible without authentication."),
            ("/api/metrics",      ["jvm", "http_requests", "process_cpu", "counter"],
             "Application Metrics Exposed", "Medium",
             "Metrics endpoint accessible. Reveals performance data and internal counters."),
            ("/api/health",       ["status", "db", "redis", "database", "diskSpace"],
             "Detailed Health Endpoint Exposed", "Low",
             "Health endpoint reveals internal service dependencies and their status."),
            ("/api/internal",     ["internal", "admin", "secret", "config"],
             "Internal API Endpoint Exposed", "High",
             "Internal API endpoint accessible from public network."),
            ("/api/backup",       ["backup", "dump", "export", "sql"],
             "API Backup Endpoint Exposed", "Critical",
             "Backup endpoint accessible. May allow full data export."),
        ]
        for path, keywords, title, severity, detail in sensitive:
            url = self.base_url + path
            try:
                r = await client.get(url, headers=self.custom_headers)
                if self._is_open(r.status_code):
                    content = r.text.lower()
                    ct = r.headers.get("content-type", "").lower()
                    # Must be JSON/text response AND contain confirming keywords
                    is_json_or_text = "application/json" in ct or "text/plain" in ct
                    has_keywords = keywords and any(kw.lower() in content for kw in keywords)
                    if is_json_or_text and has_keywords:
                        findings.append({
                            "check": title,
                            "severity": severity, "category": "API8:2023",
                            "detail": detail,
                            "evidence": f"HTTP {r.status_code} at {url} — confirming keywords found in response",
                            "cve": None, "url": url,
                            "recommendation": f"Require authentication on {path}. Apply IP allowlisting for admin endpoints."
                        })
            except Exception:
                pass
        return findings

    # ── HTTP Methods ──────────────────────────────────────────────────────────
    async def _check_http_methods(self, client) -> list:
        findings = []
        for method in ["TRACE", "TRACK"]:
            try:
                r = await client.request(method, self.base_url, headers=self.custom_headers)
                if r.status_code == 200 and method in r.text.upper():
                    findings.append({
                        "check": f"Dangerous HTTP Method Enabled: {method}",
                        "severity": "Low", "category": "API8:2023",
                        "detail": f"HTTP {method} enabled and echoes request. Enables Cross-Site Tracing (XST).",
                        "evidence": f"{method} {self.base_url} → HTTP {r.status_code}, response echoes request",
                        "cve": "CVE-2004-2320", "url": self.base_url,
                        "recommendation": f"Disable HTTP {method} in web server/API gateway configuration."
                    })
            except Exception:
                pass
        return findings

    # ── Injection ─────────────────────────────────────────────────────────────
    async def _check_injection_api(self, client) -> list:
        findings = []
        db_error_patterns = [
            (r"you have an error in your sql syntax", "MySQL SQLi"),
            (r"ORA-\d{5}:", "Oracle SQLi"),
            (r"unclosed quotation mark", "MSSQL SQLi"),
            (r"pg_query\(\).*error", "PostgreSQL SQLi"),
            (r"sqlite3\.operationalerror", "SQLite SQLi"),
            (r"\{\{.*\}\}", "Template Injection"),
            (r"freemarker\.core", "FreeMarker SSTI"),
            (r"velocity\.exception", "Velocity SSTI"),
        ]
        payloads = [
            ("sqli", "' OR '1'='1'--"),
            ("sqli", "1 AND 1=2 UNION SELECT NULL--"),
            ("ssti", "{{7*7}}"),
            ("ssti", "${7*7}"),
        ]
        endpoints = ["/api/users", "/api/search", "/api/items", "/api/products"] + self.extra_endpoints[:2]
        for ep in endpoints[:4]:
            url = self.base_url + ep
            try:
                baseline = await client.get(url, headers=self.custom_headers)
                if baseline.status_code not in (200, 400, 422):
                    continue
            except Exception:
                continue
            for ptype, payload in payloads:
                try:
                    r = await client.get(url, params={"id": payload, "q": payload, "search": payload},
                                          headers=self.custom_headers)
                    for pattern, vuln_type in db_error_patterns:
                        if (re.search(pattern, r.text, re.IGNORECASE) and
                                not re.search(pattern, baseline.text, re.IGNORECASE)):
                            findings.append({
                                "check": f"API {vuln_type} Vulnerability",
                                "severity": "Critical", "category": "API8:2023",
                                "detail": f"{vuln_type} confirmed via error pattern in API response.",
                                "evidence": f"Payload '{payload}' at {url} triggered pattern '{pattern}'",
                                "cve": None, "url": url,
                                "recommendation": "Use parameterized queries. Sanitize all API inputs. Never expose DB errors."
                            })
                            return findings
                except Exception:
                    pass
        return findings

    # ── Security Headers ──────────────────────────────────────────────────────
    async def _check_api_security_headers(self, client) -> list:
        findings = []
        try:
            r = await client.get(self.base_url, headers=self.custom_headers)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            ct = hdrs.get("content-type", "")
            if "application/json" not in ct:
                return findings  # Only check JSON APIs
            missing = []
            if "x-content-type-options" not in hdrs:
                missing.append("X-Content-Type-Options: nosniff")
            if "x-frame-options" not in hdrs and "frame-ancestors" not in hdrs.get("content-security-policy", ""):
                missing.append("X-Frame-Options: DENY")
            if missing:
                findings.append({
                    "check": "API Response Missing Security Headers",
                    "severity": "Low", "category": "API8:2023",
                    "detail": "JSON API responses missing security headers.",
                    "evidence": f"Missing headers: {', '.join(missing)}",
                    "cve": None, "url": self.base_url,
                    "recommendation": f"Add to all API responses: {'; '.join(missing)}"
                })
        except Exception:
            pass
        return findings

    # ── GraphQL ───────────────────────────────────────────────────────────────
    async def _check_graphql(self, client) -> list:
        findings = []
        graphql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/query"]
        introspection = '{"query":"{ __schema { queryType { name } types { name kind } } }"}'
        for path in graphql_paths:
            url = self.base_url + path
            try:
                r = await client.post(url, content=introspection,
                                       headers={**self.custom_headers, "Content-Type": "application/json"})
                if r.status_code == 200:
                    data = r.text
                    # Confirm actual GraphQL introspection response
                    if "__schema" in data and "queryType" in data:
                        findings.append({
                            "check": "GraphQL Introspection Enabled",
                            "severity": "Medium", "category": "API8:2023",
                            "detail": "GraphQL introspection is enabled. Attackers can enumerate the full schema, all types, queries, and mutations.",
                            "evidence": f"Introspection query returned __schema data at {url}",
                            "cve": None, "url": url,
                            "recommendation": "Disable introspection in production. Use query depth limiting and field-level authorization."
                        })
            except Exception:
                pass
        return findings

    # ── Swagger / API Docs ────────────────────────────────────────────────────
    async def _check_swagger_exposure(self, client) -> list:
        findings = []
        swagger_paths = ["/swagger.json", "/openapi.json", "/api-docs",
                          "/swagger-ui.html", "/api/swagger.json", "/v2/api-docs",
                          "/v3/api-docs", "/docs", "/redoc"]
        for path in swagger_paths:
            url = self.base_url + path
            try:
                r = await client.get(url, headers=self.custom_headers)
                if r.status_code == 200:
                    content = r.text
                    # Confirm it's actual API docs, not a custom 200 page
                    is_swagger = (
                        ('"swagger"' in content or '"openapi"' in content) and
                        '"paths"' in content
                    ) or "swagger-ui" in content.lower()
                    if is_swagger:
                        findings.append({
                            "check": "API Documentation Publicly Accessible",
                            "severity": "Medium", "category": "API9:2023",
                            "detail": "API documentation accessible without authentication. Exposes all endpoints, parameters, and schemas.",
                            "evidence": f"Swagger/OpenAPI spec confirmed at {url}",
                            "cve": None, "url": url,
                            "recommendation": "Restrict API docs to authenticated users or internal networks only."
                        })
            except Exception:
                pass
        return findings

    # ── BOLA / IDOR ───────────────────────────────────────────────────────────
    async def _check_bola(self, client) -> list:
        findings = []
        object_paths = [
            ("/api/users/1", "/api/users/2"),
            ("/api/orders/1", "/api/orders/2"),
            ("/api/accounts/1", "/api/accounts/2"),
            ("/api/v1/users/1", "/api/v1/users/2"),
        ]
        for path1, path2 in object_paths[:2]:
            url1 = self.base_url + path1
            url2 = self.base_url + path2
            try:
                r1 = await client.get(url1, headers=self.custom_headers)
                r2 = await client.get(url2, headers=self.custom_headers)
                if (self._is_open(r1.status_code) and self._is_open(r2.status_code)
                        and len(r1.text) > 20 and len(r2.text) > 20
                        and r1.text != r2.text):
                    # Both return different data — likely real objects, not a catch-all 200
                    findings.append({
                        "check": "Potential BOLA / IDOR — Sequential Object IDs",
                        "severity": "High", "category": "API1:2023",
                        "detail": "Sequential numeric IDs return different user data without ownership verification.",
                        "evidence": f"HTTP 200 with data at {url1} AND {url2} — different response bodies confirm real objects",
                        "cve": None, "url": url1,
                        "recommendation": "Use non-sequential UUIDs. Enforce object-level authorization on every request."
                    })
            except Exception:
                pass
        return findings

    # ── JWT None Algorithm ────────────────────────────────────────────────────
    async def _check_jwt_issues(self, client) -> list:
        findings = []
        # JWT with alg:none — unsigned token claiming admin role
        none_token = "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNjAwMDAwMDAwfQ."
        protected_paths = ["/api/admin", "/api/admin/users", "/api/management", "/api/v1/admin"]
        for path in protected_paths[:2]:
            url = self.base_url + path
            try:
                # Baseline without token
                baseline = await client.get(url, headers=self.custom_headers)
                if self._is_open(baseline.status_code):
                    continue  # Already open — not a JWT bypass
                r = await client.get(url, headers={**self.custom_headers,
                                                    "Authorization": f"Bearer {none_token}"})
                if self._is_open(r.status_code) and r.status_code != baseline.status_code:
                    findings.append({
                        "check": "JWT 'none' Algorithm Accepted",
                        "severity": "Critical", "category": "API2:2023",
                        "detail": "Server accepts JWT with alg:none, bypassing signature verification entirely.",
                        "evidence": f"Baseline: HTTP {baseline.status_code} → With none-alg JWT: HTTP {r.status_code} at {url}",
                        "cve": "CVE-2015-9235", "url": url,
                        "recommendation": "Explicitly reject 'none' algorithm. Use a strict allowlist of accepted JWT algorithms."
                    })
            except Exception:
                pass
        return findings

    # ── Mass Assignment ───────────────────────────────────────────────────────
    async def _check_mass_assignment(self, client) -> list:
        findings = []
        payload = {"role": "admin", "is_admin": True, "admin": 1, "privilege": "superuser"}
        endpoints = ["/api/users", "/api/profile", "/api/account", "/api/register"]
        for ep in endpoints[:2]:
            url = self.base_url + ep
            try:
                r = await client.post(url, json=payload, headers=self.custom_headers)
                if r.status_code in (200, 201):
                    resp = r.text.lower()
                    # Confirm the privileged field was actually accepted/reflected
                    if any(k in resp for k in ['"role":"admin"', '"is_admin":true',
                                                '"admin":true', '"privilege":"superuser"',
                                                "'role': 'admin'", "role: admin"]):
                        findings.append({
                            "check": "Mass Assignment — Privileged Field Accepted",
                            "severity": "High", "category": "API6:2023",
                            "detail": "API accepted and reflected privileged fields (role/admin) from request body.",
                            "evidence": f"POST {url} with {list(payload.keys())} → HTTP {r.status_code}, privileged field reflected in response",
                            "cve": None, "url": url,
                            "recommendation": "Use an explicit allowlist of accepted fields. Never bind request body directly to model."
                        })
            except Exception:
                pass
        return findings

    # ── API Versioning ────────────────────────────────────────────────────────
    async def _check_api_versioning(self, client) -> list:
        findings = []
        version_paths = ["/api/v1/", "/api/v2/", "/api/v0/", "/v1/", "/v2/"]
        for path in version_paths:
            url = self.base_url + path
            try:
                r = await client.get(url, headers=self.custom_headers)
                if self._is_open(r.status_code) and len(r.text) > 30:
                    content = r.text.lower()
                    # Confirm it's an API response, not a redirect or HTML page
                    is_api = ("application/json" in r.headers.get("content-type", "") or
                              any(kw in content for kw in ['"version"', '"api"', '"endpoints"', '"routes"']))
                    if is_api:
                        findings.append({
                            "check": f"Old API Version Accessible: {path}",
                            "severity": "Medium", "category": "API9:2023",
                            "detail": f"API version {path} is accessible and returns data. Old versions may lack security patches.",
                            "evidence": f"HTTP {r.status_code} with API content at {url}",
                            "cve": None, "url": url,
                            "recommendation": "Decommission old API versions. Redirect to latest version with deprecation notice."
                        })
            except Exception:
                pass
        return findings
