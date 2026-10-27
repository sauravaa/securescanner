# 🛡️ SecureScanner AI

**World-class AI-powered web application & API security scanner** following OWASP Testing Guide, OWASP Top 10, and OWASP API Security Top 10.

![SecureScanner AI](https://img.shields.io/badge/Security-OWASP%20Top%2010-red?style=for-the-badge)
![Python](https://img.shields.io/badge/Python-3.11+-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green?style=for-the-badge&logo=fastapi)
![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)

---

## ✨ Features

- **18+ Security Checks** — SQL Injection, XSS, CSRF, CORS, SSL/TLS, Security Headers, Open Redirect, Clickjacking, SSRF, XXE, Cookie Security, Directory Listing, Sensitive Data Exposure, and more
- **AI-Powered Analysis** — Uses Groq's free LLaMA 3 model to generate detailed vulnerability explanations
- **OWASP Top 10 Coverage** — Full checklist mapped to OWASP 2021 and API Security 2023
- **Rich Vulnerability Reports** — CVSS Score, CVE ID + NVD link, OWASP Category, Description, Impact, Exploit Scenario, Remediation
- **PDF Report Generation** — Professional dark-themed PDF reports
- **Scan History** — SQLite-backed history of all scans
- **World-Class UI** — Dark theme, animated scanner, responsive design

## 🔍 Security Checks

| Category | Checks |
|----------|--------|
| Injection | SQL Injection, XSS (Reflected), API Injection |
| Auth | CSRF, Brute Force Protection, JWT None Algorithm, Auth Bypass |
| Cryptography | SSL/TLS Version, Certificate Validity, HTTPS Enforcement |
| Misconfiguration | Security Headers (HSTS, CSP, X-Frame-Options, etc.), CORS, Server Info Disclosure |
| Sensitive Data | AWS Keys, Private Keys, JWT Tokens, Passwords in HTML, .env Exposure, .git Exposure |
| Access Control | Open Redirect, Directory Listing, BOLA/IDOR |
| API Security | Mass Assignment, Rate Limiting, GraphQL Introspection, Swagger Exposure, SSRF |

## 🚀 Quick Start

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/securescanner.git
cd securescanner
```

### 2. Create Virtual Environment
```bash
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment
```bash
cp .env.example .env
# Edit .env and add your free Groq API key
# Get free key at: https://console.groq.com
```

### 5. Run the Application
```bash
python main.py
```

Open **http://localhost:8000** in your browser.

## 🔑 Getting a Free Groq API Key

1. Visit [https://console.groq.com](https://console.groq.com)
2. Sign up for a free account
3. Create an API key
4. Add it to your `.env` file as `GROQ_API_KEY=your_key_here`

> **Note:** The scanner works without a Groq API key using built-in fallback analysis. AI-enriched descriptions require the key.

## 📋 Usage

### Web Application Scan
1. Select **Web Application** tab
2. Enter target URL (e.g., `https://example.com`)
3. Click **Scan Now**
4. View detailed report with AI analysis

### API Scan
1. Select **API / cURL** tab
2. Enter API base URL
3. Optionally add custom headers (JSON) and endpoints
4. Click **Scan Now**

## ⚠️ Legal Disclaimer

**This tool is for authorized security testing only.** Always obtain explicit written permission before scanning any application or system you do not own. Unauthorized scanning may violate computer crime laws.

## 🏗️ Architecture

```
securescanner/
├── main.py                          # FastAPI application
├── backend/
│   ├── scanners/
│   │   ├── web_scanner.py           # Web app security checks
│   │   └── api_scanner.py           # API security checks
│   ├── reports/
│   │   └── report_generator.py      # AI analysis + PDF generation
│   └── utils/
│       └── db.py                    # SQLite scan history
├── frontend/
│   ├── templates/
│   │   ├── index.html               # Main scanner UI
│   │   ├── report.html              # Interactive report page
│   │   └── report_pdf.html          # PDF report template
│   └── static/
│       ├── css/
│       │   ├── main.css             # Main styles
│       │   └── report.css           # Report styles
│       └── js/
│           └── main.js              # Frontend logic
└── requirements.txt
```

## 🛡️ Security Best Practices Implemented

- Rate limiting on scan endpoints (10/minute)
- Input validation on all user inputs
- No credentials stored in code
- CORS configured appropriately
- SQL injection prevention via parameterized queries
- No eval() or dynamic code execution
- Dependency pinning in requirements.txt

## 📄 License

MIT License — Free to use, modify, and distribute.

---

Built with ❤️ for the security community | Follow OWASP standards | Developed by Saurav Anand https://www.linkedin.com/in/sauravanandarya/
