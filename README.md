# CoverSec Technique Extractor

Extracts security testing techniques from pentest reports and outputs RAG-ready `.md` technique cards.

Each card contains a vulnerability description, its impact, and **how to test for it** — real pentester steps with tools (Burp, sqlmap, Frida, etc.).

## Setup

```bash
pip install python-docx PyPDF2
```

## Usage

### CyShield `.docx` reports

```bash
# Single report
python extractor.py "C:\path\to\report.docx" output

# Folder of reports
python extractor.py "C:\path\to\folder" output

# Filter by service type
python extractor.py "C:\path\to\folder" output --service WAPT
```

### Public PDF reports

```bash
# Single PDF
python pdf_extractor.py "C:\path\to\report.pdf" output

# Folder of PDFs
python pdf_extractor.py "C:\path\to\folder" output
```

### Clean output before each run

```bash
# Windows
rmdir /s /q output

# Linux/Mac
rm -rf output
```

## Output Example

Each vulnerability becomes a `.md` technique card:

```markdown
---
technique: "Server-Side Request Forgery"
severity: High
cvss: 7.0
cwe: "CWE-918: Server-Side Request Forgery (SSRF)"
owasp_ref: "OWASP: SSRF"
service_type: WBPT
source: 85faad0e9229
---

# Server-Side Request Forgery

## Description

The application accepts user-supplied URLs without validation,
allowing an attacker to make the server issue requests to internal
or otherwise inaccessible resources.

## Impact

An attacker can access internal services, enumerate the internal
network, and retrieve sensitive information from cloud metadata
services.

## How to Test

- Find parameters accepting URLs (webhooks, image URLs, imports).
  Try: http://127.0.0.1, http://localhost, http://169.254.169.254/latest/meta-data/
- Use Burp Collaborator to detect blind SSRF — inject your collaborator
  URL and check for DNS/HTTP callbacks
- Try bypasses: http://0x7f000001, http://[::1], http://127.1,
  http://evil.com@127.0.0.1
```

## Supported Report Types

### extractor.py (CyShield `.docx`)

| Type | Description |
|------|-------------|
| WAPT | Web Application Penetration Testing |
| EIPT | External Infrastructure Penetration Testing |
| IIPT | Internal Infrastructure Penetration Testing |
| SCR  | Source Code Review |
| WBPT | White-Box Penetration Testing |
| MAPT | Mobile Application Penetration Testing |
| DAPT | Desktop Application Penetration Testing |
| PAPT | Point of Sale Application Penetration Testing |
| ATMPT| ATM Penetration Testing |

### pdf_extractor.py (Public PDFs)

Works with any pentest report PDF — Cure53, NCC Group, Trail of Bits, X41, Bishop Fox, etc.

## Features

- **No client data in output** — all client names, project names, URLs, IPs, emails, and product names are stripped
- **Deduplication** — same technique won't appear twice
- **Test cases by technique type** — "How to Test" is mapped from the vulnerability class (SQLi, XSS, SSRF, etc.), not from report recommendations
- **40+ vulnerability patterns** covered with pentester-oriented test steps

## Files

| File | Purpose |
|------|---------|
| `extractor.py` | Parses CyShield `.docx` reports |
| `pdf_extractor.py` | Parses public PDF reports |
| `testcase_heuristics.py` | Maps vulnerability types to test cases (used by both tools) |
| `requirements.txt` | Python dependencies |

## Requirements

- Python 3.10+
- `python-docx` (for `.docx` parsing)
- `PyPDF2` (for `.pdf` parsing)
