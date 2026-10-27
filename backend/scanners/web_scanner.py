import asyncio
import re
import ssl
import socket
import datetime
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from typing import Optional
import httpx
from bs4 import BeautifulSoup


class WebScanner:
    def __init__(self, url: str):
        self.url = url if url.startswith("http") else f"https://{url}"
        self.parsed = urlparse(self.url)
        self.findings = []
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        }
        self.client_config = {
            "timeout": 20,
            "follow_redirects": True,
            "verify": False,
        }

    async def scan(self) -> list:
        async with httpx.AsyncClient(**self.client_config, headers=self.headers) as client:
            try:
                response = await client.get(self.url)
            except httpx.ConnectError as e:
                return [{"check": "Connection Failed", "severity": "Critical",
                         "detail": f"Cannot connect to target: {e}", "category": "Availability",
                         "evidence": str(e), "url": self.url}]
            except httpx.TimeoutException:
                return [{"check": "Connection Timeout", "severity": "Medium",
                         "detail": "Target did not respond within timeout.", "category": "Availability",
                         "evidence": "Request timed out after 20s", "url": self.url}]
            except Exception as e:
                return [{"check": "Scan Error", "severity": "Info",
                         "detail": str(e), "category": "Availability",
                         "evidence": str(e), "url": self.url}]

            soup = BeautifulSoup(response.text, "lxml")
            tasks = [
                self._check_security_headers(response),
                self._check_ssl_tls(),
                self._check_xss(client, soup),
                self._check_sql_injection(client, soup),
                self._check_csrf(soup, response),
                self._check_sensitive_data(response),
                self._check_open_redirect(client),
                self._check_exposed_paths(client),
                self._check_server_info(response),
                self._check_cookies(response),
                self._check_cors(client),
                self._check_ssrf_vectors(soup),
                self._check_broken_auth(client, soup),
                self._check_insecure_forms(soup),
                self._check_mixed_content(soup),
                self._check_sri(soup),
                self._check_csp(response),
                self._check_http_methods(client),
                self._check_cache_control(response),
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, list):
                    self.findings.extend(r)
        return self._deduplicate(self.findings)

    def _deduplicate(self, findings: list) -> list:
        seen = set()
        unique = []
        for f in findings:
            key = (f.get("check"), f.get("url", ""))
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    # ── Security Headers ────────────────────────────────────────────────────
    async def _check_security_headers(self, response) -> list:
        findings = []
        hdrs = {k.lower(): v for k, v in response.headers.items()}
        csp = hdrs.get("content-security-policy", "")
        xfo = hdrs.get("x-frame-options", "")

        # HSTS — only flag on HTTPS sites
        if self.url.startswith("https") and "strict-transport-security" not in hdrs:
            findings.append({
                "check": "HSTS Header Missing",
                "severity": "High", "category": "A05:2021",
                "detail": "Strict-Transport-Security header absent on HTTPS site. Enables protocol downgrade attacks.",
                "evidence": "Response headers do not contain 'Strict-Transport-Security'",
                "cve": None, "url": self.url,
                "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            })

        # X-Content-Type-Options
        if "x-content-type-options" not in hdrs:
            findings.append({
                "check": "X-Content-Type-Options Missing",
                "severity": "Low", "category": "A05:2021",
                "detail": "Missing X-Content-Type-Options allows MIME-type sniffing.",
                "evidence": "Header 'X-Content-Type-Options: nosniff' not present",
                "cve": None, "url": self.url,
                "recommendation": "Add: X-Content-Type-Options: nosniff"
            })

        # X-Frame-Options — only flag if CSP frame-ancestors also missing
        if not xfo and "frame-ancestors" not in csp:
            findings.append({
                "check": "Clickjacking Protection Missing",
                "severity": "Medium", "category": "A05:2021",
                "detail": "Neither X-Frame-Options nor CSP frame-ancestors is set. Page can be embedded in iframes.",
                "evidence": "No X-Frame-Options header and no CSP frame-ancestors directive found",
                "cve": None, "url": self.url,
                "recommendation": "Add: X-Frame-Options: DENY  or  CSP: frame-ancestors 'none'"
            })

        # CSP missing entirely
        if not csp:
            findings.append({
                "check": "Content-Security-Policy Missing",
                "severity": "High", "category": "A05:2021",
                "detail": "No CSP header found. Allows unrestricted inline scripts and external resource loading.",
                "evidence": "Content-Security-Policy header absent in HTTP response",
                "cve": None, "url": self.url,
                "recommendation": "Implement a strict CSP: Content-Security-Policy: default-src 'self'"
            })

        # Referrer-Policy
        if "referrer-policy" not in hdrs:
            findings.append({
                "check": "Referrer-Policy Missing",
                "severity": "Low", "category": "A05:2021",
                "detail": "Without Referrer-Policy, sensitive URL fragments may leak to third parties.",
                "evidence": "Referrer-Policy header not present in response",
                "cve": None, "url": self.url,
                "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin"
            })

        return findings

    # ── SSL / TLS ────────────────────────────────────────────────────────────
    async def _check_ssl_tls(self) -> list:
        findings = []
        if not self.url.startswith("https"):
            findings.append({
                "check": "Site Not Using HTTPS",
                "severity": "Critical", "category": "A02:2021",
                "detail": "All traffic transmitted in plaintext. Credentials and session tokens exposed.",
                "evidence": f"Target URL uses HTTP scheme: {self.url}",
                "cve": "CVE-2021-27853", "url": self.url,
                "recommendation": "Redirect all HTTP traffic to HTTPS. Obtain a valid TLS certificate."
            })
            return findings

        host = self.parsed.hostname
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    protocol = ssock.version()
                    cipher = ssock.cipher()

                    # Weak protocol
                    if protocol in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        findings.append({
                            "check": "Deprecated TLS Version in Use",
                            "severity": "High", "category": "A02:2021",
                            "detail": f"Server negotiated {protocol} which is deprecated and vulnerable to POODLE/BEAST.",
                            "evidence": f"TLS handshake negotiated: {protocol} | Cipher: {cipher[0] if cipher else 'N/A'}",
                            "cve": "CVE-2014-3566", "url": self.url,
                            "recommendation": "Disable TLS 1.0 and 1.1. Support only TLS 1.2 and TLS 1.3."
                        })

                    # Weak cipher
                    if cipher and any(w in cipher[0].upper() for w in ["RC4", "DES", "NULL", "EXPORT", "MD5"]):
                        findings.append({
                            "check": "Weak TLS Cipher Suite",
                            "severity": "High", "category": "A02:2021",
                            "detail": f"Weak cipher suite negotiated: {cipher[0]}",
                            "evidence": f"Cipher: {cipher[0]}, Protocol: {protocol}",
                            "cve": "CVE-2015-2808", "url": self.url,
                            "recommendation": "Disable weak ciphers. Use only AEAD cipher suites (AES-GCM, ChaCha20)."
                        })

                    # Certificate expiry
                    expire = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                    days_left = (expire - datetime.datetime.utcnow()).days
                    if days_left < 0:
                        findings.append({
                            "check": "SSL Certificate Expired",
                            "severity": "Critical", "category": "A02:2021",
                            "detail": f"SSL certificate expired {abs(days_left)} days ago.",
                            "evidence": f"Certificate notAfter: {cert['notAfter']}",
                            "cve": None, "url": self.url,
                            "recommendation": "Renew the SSL certificate immediately."
                        })
                    elif days_left < 30:
                        findings.append({
                            "check": "SSL Certificate Expiring Soon",
                            "severity": "Medium", "category": "A02:2021",
                            "detail": f"Certificate expires in {days_left} days. Expiry causes browser warnings.",
                            "evidence": f"Certificate notAfter: {cert['notAfter']} ({days_left} days remaining)",
                            "cve": None, "url": self.url,
                            "recommendation": "Renew the SSL certificate before expiry."
                        })

        except ssl.SSLCertVerificationError as e:
            findings.append({
                "check": "SSL Certificate Validation Failed",
                "severity": "Critical", "category": "A02:2021",
                "detail": "Certificate is self-signed, expired, or hostname mismatch.",
                "evidence": str(e)[:200],
                "cve": None, "url": self.url,
                "recommendation": "Use a certificate from a trusted CA. Ensure hostname matches CN/SAN."
            })
        except (socket.timeout, ConnectionRefusedError):
            pass
        except Exception:
            pass
        return findings

    # ── XSS ─────────────────────────────────────────────────────────────────
    async def _check_xss(self, client, soup) -> list:
        findings = []
        # Use a unique marker to confirm actual reflection, not coincidental match
        marker = "xss7731test"
        payloads = [
            f'<script>{marker}</script>',
            f'"><img src=x onerror=console.log({marker})>',
            f"'><svg onload=console.log('{marker}')>",
        ]

        # Form-based XSS
        for form in soup.find_all("form")[:3]:
            action = urljoin(self.url, form.get("action") or self.url)
            method = form.get("method", "get").lower()
            text_inputs = [i for i in form.find_all("input")
                           if i.get("type", "text") not in ("submit", "hidden", "checkbox", "radio", "file")]
            if not text_inputs:
                continue
            for payload in payloads[:2]:
                data = {i.get("name", "q"): payload for i in text_inputs if i.get("name")}
                if not data:
                    continue
                try:
                    r = (await client.post(action, data=data) if method == "post"
                         else await client.get(action, params=data))
                    # Confirm the raw payload is reflected unencoded
                    if marker in r.text and payload in r.text:
                        findings.append({
                            "check": "Reflected XSS via Form Input",
                            "severity": "High", "category": "A03:2021",
                            "detail": f"Form input reflected unescaped. Payload executed in browser context.",
                            "evidence": f"Payload '{payload[:60]}' reflected unencoded at {action}",
                            "cve": "CVE-2021-22145", "url": action,
                            "recommendation": "HTML-encode all user output. Implement strict CSP. Use framework auto-escaping."
                        })
                        break
                except Exception:
                    pass

        # URL parameter XSS
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        for param in list(params.keys())[:3]:
            for payload in payloads[:2]:
                test_params = {k: v for k, v in params.items()}
                test_params[param] = [payload]
                test_url = urlunparse(parsed._replace(query=urlencode(test_params, doseq=True)))
                try:
                    r = await client.get(test_url)
                    if marker in r.text and payload in r.text:
                        findings.append({
                            "check": "Reflected XSS via URL Parameter",
                            "severity": "High", "category": "A03:2021",
                            "detail": f"URL parameter '{param}' reflects input unescaped into HTML response.",
                            "evidence": f"Payload '{payload[:60]}' reflected at {test_url[:120]}",
                            "cve": "CVE-2021-22145", "url": test_url,
                            "recommendation": "Sanitize and encode all URL parameter values before rendering."
                        })
                        break
                except Exception:
                    pass
        return findings

    # ── SQL Injection ────────────────────────────────────────────────────────
    async def _check_sql_injection(self, client, soup) -> list:
        findings = []
        # Specific DB error signatures only — avoids generic "error" false positives
        db_error_patterns = [
            (r"you have an error in your sql syntax", "MySQL"),
            (r"warning: mysql_", "MySQL"),
            (r"unclosed quotation mark after the character string", "MSSQL"),
            (r"quoted string not properly terminated", "Oracle"),
            (r"ORA-\d{5}:", "Oracle"),
            (r"pg_query\(\).*error", "PostgreSQL"),
            (r"psql.*error", "PostgreSQL"),
            (r"sqlite3\.operationalerror", "SQLite"),
            (r"microsoft ole db provider for sql server", "MSSQL"),
            (r"syntax error.*near", "Generic SQL"),
            (r"invalid query", "Generic SQL"),
        ]
        payloads = ["'", "''", "' OR '1'='1'--", "1 AND 1=2"]

        for form in soup.find_all("form")[:3]:
            action = urljoin(self.url, form.get("action") or self.url)
            method = form.get("method", "get").lower()
            text_inputs = [i for i in form.find_all("input")
                           if i.get("type", "text") not in ("submit", "hidden", "file")]
            if not text_inputs:
                continue

            # Get baseline response first to avoid false positives
            try:
                baseline_data = {i.get("name", "q"): "test123" for i in text_inputs if i.get("name")}
                baseline = (await client.post(action, data=baseline_data) if method == "post"
                            else await client.get(action, params=baseline_data))
            except Exception:
                continue

            for payload in payloads:
                data = {i.get("name", "q"): payload for i in text_inputs if i.get("name")}
                if not data:
                    continue
                try:
                    r = (await client.post(action, data=data) if method == "post"
                         else await client.get(action, params=data))
                    for pattern, db_type in db_error_patterns:
                        if (re.search(pattern, r.text, re.IGNORECASE) and
                                not re.search(pattern, baseline.text, re.IGNORECASE)):
                            findings.append({
                                "check": f"SQL Injection ({db_type})",
                                "severity": "Critical", "category": "A03:2021",
                                "detail": f"{db_type} database error triggered by SQL payload. Confirms injectable parameter.",
                                "evidence": f"Payload: '{payload}' | DB error pattern '{pattern}' at {action}",
                                "cve": "CVE-2021-44228", "url": action,
                                "recommendation": "Use parameterized queries. Never concatenate user input into SQL strings."
                            })
                            return findings
                except Exception:
                    pass
        return findings

    # ── CSRF ─────────────────────────────────────────────────────────────────
    async def _check_csrf(self, soup, response) -> list:
        findings = []
        hdrs = {k.lower(): v for k, v in response.headers.items()}
        samesite_cookie = any(
            "samesite=strict" in str(v).lower() or "samesite=lax" in str(v).lower()
            for v in response.headers.getlist("set-cookie")
        ) if hasattr(response.headers, "getlist") else False

        post_forms = soup.find_all("form", method=re.compile("^post$", re.I))
        for form in post_forms:
            inputs = form.find_all("input")
            # Check for CSRF token in inputs, meta tags, or custom headers
            has_token = any(
                any(kw in (i.get("name", "") + i.get("id", "") + i.get("value", "")).lower()
                    for kw in ["csrf", "_token", "authenticity_token", "xsrf", "nonce", "__requestverificationtoken"])
                for i in inputs
            )
            # Also check meta tags for CSRF token
            meta_csrf = soup.find("meta", attrs={"name": re.compile("csrf", re.I)})
            if not has_token and not meta_csrf and not samesite_cookie:
                action = form.get("action", "N/A")
                findings.append({
                    "check": "CSRF Protection Missing on POST Form",
                    "severity": "High", "category": "A01:2021",
                    "detail": "POST form has no CSRF token, no SameSite cookie, and no meta CSRF tag.",
                    "evidence": f"Form action='{action}' — no csrf/token input field or meta tag found",
                    "cve": None, "url": self.url,
                    "recommendation": "Add a per-session CSRF token to all state-changing forms. Set SameSite=Strict on session cookies."
                })
        return findings

    # ── Sensitive Data Exposure ───────────────────────────────────────────────
    async def _check_sensitive_data(self, response) -> list:
        findings = []
        content = response.text

        checks = [
            ("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b", "Critical",
             "AWS access key exposed in page source. Immediate credential rotation required."),
            ("Private Key Material", r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Critical",
             "Private key found in page source. All signed certificates must be revoked."),
            ("JWT Token", r"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b", "Critical",
             "JWT token exposed. Attacker can use it to impersonate authenticated users."),
            ("Hardcoded Password", r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{6,}["\']', "High",
             "Hardcoded password found in HTML source."),
            ("Internal IP Address", r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b", "Medium",
             "Internal network IP address leaked in response. Reveals network topology."),
            ("Stack Trace / Debug Info", r"(?i)(traceback \(most recent call\)|at [a-z]+\.[a-z]+\(.*\.java:\d+\)|exception in thread|fatal error:|unhandled exception)", "High",
             "Stack trace or debug output exposed. Reveals internal code paths and technology stack."),
            ("Database Connection String", r"(?i)(server=.*;database=|data source=.*;initial catalog=|mongodb://|mysql://|postgresql://)[^\s\"'<]{8,}", "Critical",
             "Database connection string found in response. Contains credentials and host information."),
        ]

        for name, pattern, severity, detail in checks:
            match = re.search(pattern, content)
            if match:
                # Truncate evidence to avoid leaking full secrets
                raw = match.group()
                evidence_val = raw[:40] + "..." if len(raw) > 40 else raw
                findings.append({
                    "check": f"Sensitive Data Exposure: {name}",
                    "severity": severity, "category": "A02:2021",
                    "detail": detail,
                    "evidence": f"Pattern matched in response body: {evidence_val}",
                    "cve": None, "url": self.url,
                    "recommendation": "Remove all secrets from source code and HTML. Use environment variables and secret managers."
                })
        return findings

    # ── Open Redirect ────────────────────────────────────────────────────────
    async def _check_open_redirect(self, client) -> list:
        findings = []
        parsed = urlparse(self.url)
        params = parse_qs(parsed.query)
        redirect_params = [p for p in params
                           if any(k in p.lower() for k in ["url", "redirect", "next", "return", "goto", "dest", "target", "redir"])]
        for param in redirect_params:
            test_url = urlunparse(parsed._replace(query=urlencode({param: "https://evil-test.com"}, doseq=True)))
            try:
                r = await client.get(test_url, follow_redirects=False)
                loc = r.headers.get("location", "")
                # Only flag if actually redirected to our injected domain
                if "evil-test.com" in loc:
                    findings.append({
                        "check": "Open Redirect",
                        "severity": "Medium", "category": "A01:2021",
                        "detail": f"Parameter '{param}' redirects to attacker-controlled URL without validation.",
                        "evidence": f"GET {test_url[:100]} → Location: {loc}",
                        "cve": None, "url": test_url,
                        "recommendation": "Validate redirect URLs against an allowlist of trusted domains."
                    })
            except Exception:
                pass
        return findings

    # ── Cookies ──────────────────────────────────────────────────────────────
    async def _check_cookies(self, response) -> list:
        findings = []
        raw_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
        if not raw_cookies:
            raw_set = response.headers.get("set-cookie", "")
            raw_cookies = [raw_set] if raw_set else []

        # Also check httpx cookies
        for name in response.cookies.keys():
            cookie_str = ""
            for raw in raw_cookies:
                if name.lower() in raw.lower():
                    cookie_str = raw.lower()
                    break

            is_https = self.url.startswith("https")
            has_secure = "secure" in cookie_str
            has_httponly = "httponly" in cookie_str
            has_samesite = "samesite" in cookie_str

            if is_https and not has_secure:
                findings.append({
                    "check": "Cookie Missing Secure Flag",
                    "severity": "Medium", "category": "A02:2021",
                    "detail": f"Cookie '{name}' can be transmitted over unencrypted HTTP connections.",
                    "evidence": f"Set-Cookie: {name}=... (Secure flag absent)",
                    "cve": None, "url": self.url,
                    "recommendation": f"Set the Secure flag on cookie '{name}'."
                })
            if not has_httponly:
                findings.append({
                    "check": "Cookie Missing HttpOnly Flag",
                    "severity": "Medium", "category": "A02:2021",
                    "detail": f"Cookie '{name}' is accessible via JavaScript. XSS can steal this cookie.",
                    "evidence": f"Set-Cookie: {name}=... (HttpOnly flag absent)",
                    "cve": None, "url": self.url,
                    "recommendation": f"Set the HttpOnly flag on cookie '{name}'."
                })
            if not has_samesite:
                findings.append({
                    "check": "Cookie Missing SameSite Attribute",
                    "severity": "Low", "category": "A01:2021",
                    "detail": f"Cookie '{name}' sent on cross-site requests, enabling CSRF attacks.",
                    "evidence": f"Set-Cookie: {name}=... (SameSite attribute absent)",
                    "cve": None, "url": self.url,
                    "recommendation": f"Add SameSite=Strict or SameSite=Lax to cookie '{name}'."
                })
        return findings

    # ── CORS ─────────────────────────────────────────────────────────────────
    async def _check_cors(self, client) -> list:
        findings = []
        try:
            r = await client.get(self.url, headers={"Origin": "https://evil-cors-test.com"})
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "false")
            # Wildcard + credentials is spec-invalid but some servers do it
            if acao == "*" and acac.lower() == "true":
                findings.append({
                    "check": "CORS: Wildcard Origin with Credentials",
                    "severity": "Critical", "category": "A01:2021",
                    "detail": "ACAO: * combined with ACAC: true allows any site to make credentialed cross-origin requests.",
                    "evidence": f"Access-Control-Allow-Origin: {acao} | Access-Control-Allow-Credentials: {acac}",
                    "cve": None, "url": self.url,
                    "recommendation": "Never combine ACAO: * with ACAC: true. Use explicit origin allowlist."
                })
            elif "evil-cors-test.com" in acao:
                # Server reflected our injected origin — confirmed misconfiguration
                findings.append({
                    "check": "CORS: Arbitrary Origin Reflected",
                    "severity": "High", "category": "A01:2021",
                    "detail": "Server reflects any Origin header value in ACAO response, enabling cross-origin data theft.",
                    "evidence": f"Sent Origin: https://evil-cors-test.com → ACAO: {acao}",
                    "cve": None, "url": self.url,
                    "recommendation": "Validate Origin against a strict allowlist. Do not reflect arbitrary origins."
                })
        except Exception:
            pass
        return findings

    # ── Exposed Sensitive Paths ───────────────────────────────────────────────
    async def _check_exposed_paths(self, client) -> list:
        findings = []
        checks = [
            ("/.env",        ["DB_PASSWORD", "APP_KEY", "SECRET_KEY", "DATABASE_URL", "AWS_SECRET"],
             "Exposed .env File", "Critical",
             ".env file publicly accessible. Contains database credentials and secret keys."),
            ("/.git/HEAD",   ["ref:", "refs/heads/"],
             "Exposed Git Repository", "Critical",
             ".git directory accessible. Full source code may be downloadable."),
            ("/.git/config", ["[core]", "[remote"],
             "Exposed Git Config", "Critical",
             "Git config file exposed. Reveals repository URLs and configuration."),
            ("/backup.zip",  [],
             "Backup Archive Exposed", "Critical",
             "Backup archive publicly accessible. May contain full application source and data."),
            ("/phpinfo.php", ["PHP Version", "phpinfo()"],
             "PHP Info Page Exposed", "High",
             "phpinfo() output exposed. Reveals PHP configuration, loaded modules, and server paths."),
            ("/server-status", ["Apache Server Status", "requests currently being processed"],
             "Apache Server Status Exposed", "Medium",
             "Apache mod_status page exposed. Reveals active connections and request details."),
            ("/actuator",    ["links", "health", "beans"],
             "Spring Boot Actuator Exposed", "High",
             "Spring Boot Actuator endpoint exposed. May reveal env vars, beans, and heap dumps."),
            ("/actuator/env", ["propertySources", "activeProfiles"],
             "Spring Actuator /env Exposed", "Critical",
             "Spring Actuator /env exposes all environment variables including secrets."),
            ("/wp-config.php.bak", ["DB_NAME", "DB_PASSWORD"],
             "WordPress Config Backup Exposed", "Critical",
             "WordPress config backup file accessible. Contains database credentials."),
            ("/config.php",  ["DB_PASS", "db_password", "mysql_connect"],
             "Config File Exposed", "Critical",
             "PHP config file accessible. Contains database credentials."),
        ]
        for path, keywords, title, severity, detail in checks:
            url = urljoin(self.url, path)
            try:
                r = await client.get(url)
                if r.status_code == 200:
                    content = r.text
                    # Require keyword confirmation to avoid false positives on custom 200 error pages
                    if not keywords or any(kw in content for kw in keywords):
                        findings.append({
                            "check": title,
                            "severity": severity, "category": "A05:2021",
                            "detail": detail,
                            "evidence": f"HTTP 200 at {url} with confirming content keywords",
                            "cve": None, "url": url,
                            "recommendation": f"Block public access to {path} via web server configuration."
                        })
            except Exception:
                pass
        return findings

    # ── Server Info Disclosure ────────────────────────────────────────────────
    async def _check_server_info(self, response) -> list:
        findings = []
        server = response.headers.get("Server", "")
        powered = response.headers.get("X-Powered-By", "")
        aspnet = response.headers.get("X-AspNet-Version", "")
        aspnetmvc = response.headers.get("X-AspNetMvc-Version", "")

        # Only flag if version number is present (e.g. "Apache/2.4.51" not just "Apache")
        if server and re.search(r"[\d./]", server):
            findings.append({
                "check": "Server Version Disclosed in Header",
                "severity": "Low", "category": "A05:2021",
                "detail": "Server header reveals exact software version, aiding targeted exploit selection.",
                "evidence": f"Server: {server}",
                "cve": None, "url": self.url,
                "recommendation": "Configure web server to suppress or genericize the Server header."
            })
        if powered:
            findings.append({
                "check": "Technology Stack Disclosed via X-Powered-By",
                "severity": "Low", "category": "A05:2021",
                "detail": "X-Powered-By reveals backend technology and version to attackers.",
                "evidence": f"X-Powered-By: {powered}",
                "cve": None, "url": self.url,
                "recommendation": "Remove X-Powered-By header from all responses."
            })
        if aspnet:
            findings.append({
                "check": "ASP.NET Version Disclosed",
                "severity": "Low", "category": "A05:2021",
                "detail": "X-AspNet-Version header reveals exact .NET framework version.",
                "evidence": f"X-AspNet-Version: {aspnet}",
                "cve": None, "url": self.url,
                "recommendation": "Set <httpRuntime enableVersionHeader='false'/> in web.config."
            })
        return findings

    # ── Broken Auth / Brute Force ─────────────────────────────────────────────
    async def _check_broken_auth(self, client, soup) -> list:
        findings = []
        login_forms = [f for f in soup.find_all("form")
                       if any(kw in (f.get("action", "") + f.get_text()).lower()
                              for kw in ["login", "signin", "sign-in", "authenticate", "logon"])]
        for form in login_forms[:1]:
            action = urljoin(self.url, form.get("action") or self.url)
            inputs = form.find_all("input")
            data = {}
            for i in inputs:
                name = i.get("name", "")
                itype = i.get("type", "text").lower()
                if itype in ("submit", "hidden", "checkbox"):
                    continue
                if any(k in name.lower() for k in ["user", "email", "login", "name"]):
                    data[name] = "testuser@test.com"
                elif "pass" in name.lower():
                    data[name] = "wrongpassword123"
                elif name:
                    data[name] = "test"
            if len(data) < 2:
                continue
            try:
                # Send 6 rapid requests and check for rate limiting
                tasks = [client.post(action, data=data) for _ in range(6)]
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                valid = [r for r in responses if not isinstance(r, Exception)]
                status_codes = [r.status_code for r in valid]
                has_rate_limit = any(c in status_codes for c in [429, 423, 503])
                has_captcha = any("captcha" in r.text.lower() or "recaptcha" in r.text.lower()
                                  for r in valid)
                if valid and not has_rate_limit and not has_captcha:
                    findings.append({
                        "check": "Login Endpoint Has No Brute Force Protection",
                        "severity": "High", "category": "A07:2021",
                        "detail": "Login form accepts unlimited rapid requests with no rate limiting or CAPTCHA.",
                        "evidence": f"6 rapid POST requests to {action} — status codes: {status_codes}, no 429/CAPTCHA",
                        "cve": None, "url": action,
                        "recommendation": "Implement rate limiting (max 5 attempts/min), account lockout, and CAPTCHA."
                    })
            except Exception:
                pass
        return findings

    # ── Insecure Forms ────────────────────────────────────────────────────────
    async def _check_insecure_forms(self, soup) -> list:
        findings = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            # Only flag if action explicitly uses http://
            if action.startswith("http://"):
                findings.append({
                    "check": "Form Action Submits Over HTTP",
                    "severity": "High", "category": "A02:2021",
                    "detail": "Form data including credentials transmitted over unencrypted HTTP.",
                    "evidence": f"<form action='{action}' method='{form.get('method','get')}'>",
                    "cve": None, "url": self.url,
                    "recommendation": "Change form action to use HTTPS."
                })
            for inp in form.find_all("input"):
                if inp.get("type", "").lower() == "password":
                    if form.get("method", "get").lower() == "get":
                        findings.append({
                            "check": "Password Submitted via GET Method",
                            "severity": "Critical", "category": "A02:2021",
                            "detail": "Password field in a GET form. Credentials appear in URL, browser history, and server logs.",
                            "evidence": f"<input type='password' name='{inp.get('name','')}' in GET form action='{form.get('action','')}'",
                            "cve": None, "url": self.url,
                            "recommendation": "Change form method to POST. Never submit passwords via GET."
                        })
                    if inp.get("autocomplete", "").lower() != "off":
                        findings.append({
                            "check": "Password Field Allows Autocomplete",
                            "severity": "Low", "category": "A02:2021",
                            "detail": "Browser may cache password in autocomplete history.",
                            "evidence": f"<input type='password' name='{inp.get('name','')}' — autocomplete not set to 'off'>",
                            "cve": None, "url": self.url,
                            "recommendation": "Add autocomplete='off' to password input fields."
                        })
        return findings

    # ── Mixed Content ─────────────────────────────────────────────────────────
    async def _check_mixed_content(self, soup) -> list:
        findings = []
        if not self.url.startswith("https"):
            return findings
        insecure = []
        for tag in soup.find_all(["script", "img", "link", "iframe", "audio", "video", "source"]):
            src = tag.get("src") or tag.get("href") or ""
            if src.startswith("http://"):
                insecure.append(f"<{tag.name} src='{src[:80]}'>")
        if insecure:
            findings.append({
                "check": "Mixed Content (HTTP Resources on HTTPS Page)",
                "severity": "Medium", "category": "A02:2021",
                "detail": f"HTTPS page loads {len(insecure)} resource(s) over HTTP. Browsers block or warn on mixed content.",
                "evidence": " | ".join(insecure[:3]),
                "cve": None, "url": self.url,
                "recommendation": "Update all resource URLs to use HTTPS."
            })
        return findings

    # ── Subresource Integrity ─────────────────────────────────────────────────
    async def _check_sri(self, soup) -> list:
        findings = []
        missing = []
        cdn_patterns = ["cdn.", "ajax.googleapis", "cdnjs.", "unpkg.com", "jsdelivr.net",
                        "stackpath.", "cloudflare.com", "bootstrapcdn"]
        for tag in soup.find_all(["script", "link"]):
            src = tag.get("src") or tag.get("href") or ""
            is_external_cdn = any(p in src for p in cdn_patterns)
            if is_external_cdn and not tag.get("integrity"):
                missing.append(src[:80])
        if missing:
            findings.append({
                "check": "Subresource Integrity (SRI) Missing on CDN Resources",
                "severity": "Medium", "category": "A08:2021",
                "detail": f"{len(missing)} CDN-hosted script(s)/stylesheet(s) loaded without SRI hash. CDN compromise would inject malicious code.",
                "evidence": "Missing integrity attribute on: " + " | ".join(missing[:3]),
                "cve": None, "url": self.url,
                "recommendation": "Add integrity='sha384-...' and crossorigin='anonymous' to all CDN resources."
            })
        return findings

    # ── CSP Analysis ──────────────────────────────────────────────────────────
    async def _check_csp(self, response) -> list:
        findings = []
        csp = response.headers.get("Content-Security-Policy", "")
        if not csp:
            return findings  # Already flagged in _check_security_headers
        if "'unsafe-inline'" in csp and "script-src" in csp:
            findings.append({
                "check": "CSP: unsafe-inline Allows Inline Script Execution",
                "severity": "High", "category": "A05:2021",
                "detail": "CSP script-src contains 'unsafe-inline', negating XSS protection entirely.",
                "evidence": f"Content-Security-Policy: {csp[:200]}",
                "cve": None, "url": self.url,
                "recommendation": "Remove 'unsafe-inline'. Use nonces or hashes for legitimate inline scripts."
            })
        if "'unsafe-eval'" in csp:
            findings.append({
                "check": "CSP: unsafe-eval Allows Dynamic Code Execution",
                "severity": "Medium", "category": "A05:2021",
                "detail": "CSP contains 'unsafe-eval', allowing eval() and Function() which can be abused in XSS.",
                "evidence": f"Content-Security-Policy: {csp[:200]}",
                "cve": None, "url": self.url,
                "recommendation": "Remove 'unsafe-eval'. Refactor code to avoid eval()."
            })
        # Wildcard in script-src
        script_src = re.search(r"script-src[^;]*", csp)
        if script_src and re.search(r"(?<!\w)\*(?!\w)", script_src.group()):
            findings.append({
                "check": "CSP: Wildcard in script-src",
                "severity": "High", "category": "A05:2021",
                "detail": "Wildcard (*) in script-src allows scripts from any origin, defeating CSP.",
                "evidence": f"script-src directive: {script_src.group()[:150]}",
                "cve": None, "url": self.url,
                "recommendation": "Replace wildcard with explicit trusted origins in script-src."
            })
        return findings

    # ── HTTP Methods ──────────────────────────────────────────────────────────
    async def _check_http_methods(self, client) -> list:
        findings = []
        for method in ["TRACE", "TRACK"]:
            try:
                r = await client.request(method, self.url)
                # TRACE is only dangerous if it echoes back the request body
                if r.status_code == 200 and method in r.text.upper():
                    findings.append({
                        "check": f"HTTP {method} Method Enabled (XST Risk)",
                        "severity": "Low", "category": "A05:2021",
                        "detail": f"HTTP {method} is enabled and echoes request headers. Enables Cross-Site Tracing (XST).",
                        "evidence": f"{method} {self.url} → HTTP {r.status_code}, response contains request echo",
                        "cve": "CVE-2004-2320", "url": self.url,
                        "recommendation": f"Disable HTTP {method} method in web server configuration."
                    })
            except Exception:
                pass
        return findings

    # ── Cache Control ─────────────────────────────────────────────────────────
    async def _check_cache_control(self, response) -> list:
        findings = []
        hdrs = {k.lower(): v.lower() for k, v in response.headers.items()}
        cc = hdrs.get("cache-control", "")
        pragma = hdrs.get("pragma", "")
        content_type = hdrs.get("content-type", "")

        # Only flag for HTML pages that likely contain sensitive data
        if "text/html" in content_type:
            if not cc or ("no-store" not in cc and "no-cache" not in cc and "private" not in cc):
                findings.append({
                    "check": "Sensitive Page Missing Cache-Control Headers",
                    "severity": "Low", "category": "A02:2021",
                    "detail": "HTML response lacks Cache-Control: no-store. Browsers and proxies may cache sensitive page content.",
                    "evidence": f"Cache-Control: '{cc or 'absent'}' | Pragma: '{pragma or 'absent'}'",
                    "cve": None, "url": self.url,
                    "recommendation": "Add Cache-Control: no-store, no-cache, must-revalidate to sensitive pages."
                })
        return findings

    # ── SSRF Vectors ──────────────────────────────────────────────────────────
    async def _check_ssrf_vectors(self, soup) -> list:
        findings = []
        ssrf_keywords = ["url", "uri", "link", "src", "source", "fetch", "load",
                         "import", "include", "file", "path", "endpoint", "webhook", "callback"]
        for form in soup.find_all("form")[:3]:
            for inp in form.find_all("input"):
                name = inp.get("name", "").lower()
                placeholder = inp.get("placeholder", "").lower()
                itype = inp.get("type", "text").lower()
                if itype == "url" or any(kw in name or kw in placeholder for kw in ssrf_keywords):
                    action = urljoin(self.url, form.get("action") or self.url)
                    findings.append({
                        "check": "Potential SSRF Input Vector",
                        "severity": "Medium", "category": "A10:2021",
                        "detail": f"Input field '{inp.get('name', 'unknown')}' accepts URL/path values. If server fetches this URL, SSRF is possible.",
                        "evidence": f"<input name='{inp.get('name','')}' type='{itype}' placeholder='{inp.get('placeholder','')}' in form action='{action}'",
                        "cve": None, "url": action,
                        "recommendation": "Validate and allowlist URLs server-side. Block requests to internal IP ranges."
                    })
        return findings
