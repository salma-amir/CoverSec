"""
CoverSec PDF Technique Extractor
Extracts security techniques from public pentest report PDFs
(Cure53, Trail of Bits, NCC Group, X41, Bishop Fox, etc.)

Unlike CyShield .docx reports which have one template, these PDFs
come from 85+ firms with different formats. This parser uses heuristics
to detect finding boundaries and extract technique data.

Usage:
    python pdf_extractor.py <input_folder_or_file> <output_folder>
"""

import argparse
import hashlib
import io
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

import PyPDF2
from testcase_heuristics import get_test_cases, generalize_title

if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PDFFinding:
    finding_id: str = ""
    title: str = ""
    severity: str = ""
    description: str = ""
    impact: str = ""
    recommendations: str = ""
    cwe: str = ""
    cve: str = ""
    source_file: str = ""


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------

def extract_full_text(pdf_path: Path) -> str:
    """Extract all text from a PDF, normalize spacing."""
    try:
        with open(pdf_path, "rb") as f:
            reader = PyPDF2.PdfReader(f)
            parts = []
            for page in reader.pages:
                text = page.extract_text()
                if text:
                    # Normalize excessive spaces (ToB style PDFs)
                    text = re.sub(r"(\w)   +(\w)", r"\1 \2", text)
                    text = text.replace("\xa0", " ")
                    parts.append(text)
            return "\n".join(parts)
    except Exception:
        return ""


# ---------------------------------------------------------------------------
# Finding detection patterns (multi-firm heuristics)
# ---------------------------------------------------------------------------

# Pattern 1: Cure53 style — "ID-XX-XXX Component: Title (Severity)"
CURE53_RE = re.compile(
    r"([A-Z]{2,6}-\d{2}-\d{3})\s+(.+?)\s*\((Critical|High|Medium|Low|Info)\)",
    re.IGNORECASE,
)

# Pattern 2: Trail of Bits style — "Finding ID: TOB-XXX-NNN" + "Severity: X"
TOB_ID_RE = re.compile(r"Finding\s+ID:\s*(TOB-[\w-]+)", re.IGNORECASE)
TOB_SEV_RE = re.compile(r"Severity:\s*(Critical|High|Medium|Low|Informational|Undetermined)", re.IGNORECASE)

# Pattern 3: NCC Group style — numbered findings with severity
NCC_RE = re.compile(
    r"(?:Finding|Issue)\s*(?:#?\s*\d+|[A-Z]+-\d+)[:\s]+(.+?)(?:\n|$)",
    re.IGNORECASE,
)

# Pattern 4: Generic numbered findings — "1. Title" or "Finding 1:" or "Issue 1:"
GENERIC_FINDING_RE = re.compile(
    r"(?:^|\n)\s*(?:(?:Finding|Issue|Vulnerability)\s*#?\s*(\d+)|(\d+)\.\s+)[\s:]+([^\n]{10,120})",
    re.IGNORECASE,
)

# Pattern 5: Severity in brackets or after colon
SEVERITY_RE = re.compile(
    r"\b(Critical|High|Medium|Low|Informational|Info|Moderate|Minor|Notice)\b",
    re.IGNORECASE,
)

# CVE and CWE patterns
CVE_RE = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)
CWE_RE = re.compile(r"(CWE-\d+(?::\s*[^\n]{5,80})?)", re.IGNORECASE)

# Section markers
DESCRIPTION_RE = re.compile(r"^(?:Description|Details|Overview|Summary)\s*:?\s*$", re.IGNORECASE | re.MULTILINE)
IMPACT_RE = re.compile(r"^(?:Impact|Risk|Consequence|Business Impact)\s*:?\s*$", re.IGNORECASE | re.MULTILINE)
RECOMMENDATION_RE = re.compile(
    r"^(?:Recommendation|Remediation|Mitigation|Fix|Resolution|Suggested Fix)\s*s?\s*:?\s*$",
    re.IGNORECASE | re.MULTILINE,
)


# ---------------------------------------------------------------------------
# Cure53 parser
# ---------------------------------------------------------------------------

def parse_cure53(text: str, source: str) -> list[PDFFinding]:
    """Parse Cure53-style reports."""
    findings = []
    matches = list(CURE53_RE.finditer(text))

    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        block = text[start:end]

        finding = PDFFinding(
            finding_id=m.group(1),
            title=m.group(2).strip(),
            severity=m.group(3).capitalize(),
            source_file=source,
        )

        # Extract description — everything after the title line until recommendation
        title_end = block.find("\n", len(m.group(0)))
        if title_end == -1:
            title_end = len(m.group(0))

        rec_match = re.search(r"It is recommended", block[title_end:], re.IGNORECASE)
        if rec_match:
            finding.description = block[title_end:title_end + rec_match.start()].strip()
            finding.recommendations = block[title_end + rec_match.start():].strip()
            # Trim recommendation to end of paragraph
            next_finding = CURE53_RE.search(finding.recommendations[20:])
            if next_finding:
                finding.recommendations = finding.recommendations[:20 + next_finding.start()].strip()
        else:
            finding.description = block[title_end:].strip()

        # Extract CVE/CWE
        cves = CVE_RE.findall(block)
        cwes = CWE_RE.findall(block)
        if cves:
            finding.cve = ", ".join(set(cves))
        if cwes:
            finding.cwe = cwes[0]

        # Clean up description — limit length
        finding.description = finding.description[:2000]
        finding.recommendations = finding.recommendations[:1000]

        if finding.description and len(finding.description) > 20:
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Trail of Bits parser
# ---------------------------------------------------------------------------

def parse_tob(text: str, source: str) -> list[PDFFinding]:
    """Parse Trail of Bits style reports."""
    findings = []
    id_matches = list(TOB_ID_RE.finditer(text))

    if not id_matches:
        return []

    for i, m in enumerate(id_matches):
        start = max(0, m.start() - 500)  # Look back for title and severity
        end = id_matches[i + 1].start() - 500 if i + 1 < len(id_matches) else min(m.start() + 3000, len(text))
        block = text[start:end]

        finding = PDFFinding(
            finding_id=m.group(1),
            source_file=source,
        )

        # Find severity near the ID
        sev_match = TOB_SEV_RE.search(block)
        if sev_match:
            finding.severity = sev_match.group(1).capitalize()

        # Find title — usually the numbered heading before the ID
        title_match = re.search(r"(\d+)\s*\.\s*([^\n]{10,150})", block)
        if title_match:
            finding.title = title_match.group(2).strip()
        else:
            # Try to get title from text near finding ID
            pre_text = text[max(0, m.start() - 300):m.start()]
            lines = [l.strip() for l in pre_text.split("\n") if l.strip() and len(l.strip()) > 10]
            if lines:
                finding.title = lines[-1][:120]

        # Extract description
        desc_start = block.find("Description")
        if desc_start != -1:
            desc_text = block[desc_start + 12:]
            # End at next section
            for marker in ["Exploit Scenario", "Recommendations", "Recommendation", "Short Term", "Long Term"]:
                idx = desc_text.find(marker)
                if idx > 0:
                    desc_text = desc_text[:idx]
                    break
            finding.description = desc_text.strip()[:2000]

        # Extract recommendations
        rec_start = block.find("Recommend")
        if rec_start != -1:
            rec_text = block[rec_start:]
            # Limit
            finding.recommendations = rec_text.strip()[:1000]

        # CVE/CWE
        cves = CVE_RE.findall(block)
        cwes = CWE_RE.findall(block)
        if cves:
            finding.cve = ", ".join(set(cves))
        if cwes:
            finding.cwe = cwes[0]

        if finding.title and finding.description and len(finding.description) > 20:
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Generic parser — catches most other formats
# ---------------------------------------------------------------------------

def parse_generic(text: str, source: str) -> list[PDFFinding]:
    """Generic parser using heuristics to find findings in any report format."""
    findings = []

    # Strategy: split text into chunks at likely finding boundaries
    # Look for patterns like "Finding N:", "Issue N:", numbered headings with severity

    # Try to find structured findings with severity mentions
    chunks = re.split(
        r"(?=(?:Finding|Issue|Vulnerability)\s*#?\s*\d+[\s:.])"
        r"|(?=\n\d+\.\d+\s+[A-Z])"           # "3.1 Title"
        r"|(?=\n[A-Z]+-\d{2,4}[\s:])"         # "VULN-001:"
        r"|(?=\n#{1,3}\s+(?:Finding|Issue))",  # markdown headings
        text,
    )

    for chunk in chunks:
        if len(chunk) < 50:
            continue

        # Must have at least one severity indicator
        sev_match = SEVERITY_RE.search(chunk[:500])
        if not sev_match:
            continue

        finding = PDFFinding(source_file=source)
        finding.severity = sev_match.group(1).capitalize()
        if finding.severity == "Moderate":
            finding.severity = "Medium"
        if finding.severity in ("Info", "Minor"):
            finding.severity = "Low"

        # Try to extract title from first meaningful line
        lines = [l.strip() for l in chunk.split("\n") if l.strip()]
        if lines:
            # Title is usually the first line (possibly with finding ID)
            first_line = lines[0][:150]
            # Extract finding ID if present
            id_match = re.match(r"([A-Z]+-?\d{2,4}|Finding\s*#?\d+|Issue\s*#?\d+|\d+\.\d+)", first_line)
            if id_match:
                finding.finding_id = id_match.group(1)
                finding.title = first_line[id_match.end():].strip(" :.–—-")
            else:
                finding.title = first_line.strip(" :.–—-")

        if not finding.title or len(finding.title) < 5:
            continue

        # Remove severity from title if it's at the end
        finding.title = re.sub(r"\s*\((Critical|High|Medium|Low|Info)\)\s*$", "", finding.title, flags=re.IGNORECASE)

        # Extract description
        desc_match = DESCRIPTION_RE.search(chunk)
        if desc_match:
            desc_text = chunk[desc_match.end():]
            # End at next section
            for pattern in [IMPACT_RE, RECOMMENDATION_RE]:
                m = pattern.search(desc_text)
                if m:
                    desc_text = desc_text[:m.start()]
                    break
            finding.description = desc_text.strip()[:2000]
        else:
            # Use the body text as description (skip first line = title)
            body = "\n".join(lines[1:])[:2000]
            finding.description = body

        # Extract impact
        imp_match = IMPACT_RE.search(chunk)
        if imp_match:
            imp_text = chunk[imp_match.end():]
            rec_match = RECOMMENDATION_RE.search(imp_text)
            if rec_match:
                imp_text = imp_text[:rec_match.start()]
            finding.impact = imp_text.strip()[:1000]

        # Extract recommendations
        rec_match = RECOMMENDATION_RE.search(chunk)
        if rec_match:
            finding.recommendations = chunk[rec_match.end():].strip()[:1000]

        # CVE/CWE
        cves = CVE_RE.findall(chunk)
        cwes = CWE_RE.findall(chunk)
        if cves:
            finding.cve = ", ".join(set(cves))
        if cwes:
            finding.cwe = cwes[0]

        # Generate ID if missing
        if not finding.finding_id:
            h = hashlib.sha256(f"{source}:{finding.title}".encode()).hexdigest()[:6]
            finding.finding_id = f"PUB-{h}"

        if finding.description and len(finding.description) > 30:
            findings.append(finding)

    return findings


# ---------------------------------------------------------------------------
# Detect firm and route to appropriate parser
# ---------------------------------------------------------------------------

def detect_and_parse(text: str, source: str) -> list[PDFFinding]:
    """Detect report format and parse accordingly."""
    findings = []

    # Try Cure53 first (very distinctive pattern)
    if CURE53_RE.search(text):
        findings = parse_cure53(text, source)
        if findings:
            return findings

    # Try Trail of Bits
    if "TOB-" in text and "Finding ID" in text:
        findings = parse_tob(text, source)
        if findings:
            return findings

    # Fall back to generic parser
    findings = parse_generic(text, source)
    return findings


# ---------------------------------------------------------------------------
# Sanitize and output
# ---------------------------------------------------------------------------

URL_RE = re.compile(r"https?://\S+")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")


def _sanitize(text: str) -> str:
    """Light sanitization — remove URLs and emails."""
    result = URL_RE.sub("", text)
    result = EMAIL_RE.sub("", result)
    result = re.sub(r"\s{2,}", " ", result)
    result = re.sub(r"\n{3,}", "\n\n", result)
    return result.strip()


def _escape_yaml(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def finding_to_markdown(finding: PDFFinding) -> str:
    """Convert a PDFFinding to a technique card .md."""
    desc = _sanitize(finding.description)
    impact = _sanitize(finding.impact)
    recs = _sanitize(finding.recommendations)

    lines = ["---"]
    title = generalize_title(finding.title)
    lines.append(f'technique: "{_escape_yaml(title)}"')
    lines.append(f"severity: {finding.severity}")
    if finding.cwe:
        lines.append(f'cwe: "{_escape_yaml(finding.cwe)}"')
    if finding.cve:
        lines.append(f'cve: "{_escape_yaml(finding.cve)}"')
    title = generalize_title(finding.title)
    source_hash = hashlib.sha256(
        f"{finding.source_file}:{finding.finding_id}".encode()
    ).hexdigest()[:12]
    lines.append(f"source: {source_hash}")
    lines.append(f"source_type: public")
    lines.append("---")
    lines.append("")
    lines.append(f"# {title}")
    lines.append("")

    if desc:
        lines.append("## Description")
        lines.append("")
        lines.append(desc)
        lines.append("")

    if impact:
        lines.append("## Impact")
        lines.append("")
        lines.append(impact)
        lines.append("")

    # Get test cases by matching technique title + CWE
    test_cases = get_test_cases(title, finding.cwe or "")
    if test_cases:
        lines.append("## How to Test")
        lines.append("")
        for tc in test_cases:
            lines.append(f"- {tc}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def process_pdf(pdf_path: Path) -> list[PDFFinding]:
    text = extract_full_text(pdf_path)
    if not text or len(text) < 200:
        return []
    source = pdf_path.name
    return detect_and_parse(text, source)


def process_folder(input_folder: str, output_folder: str):
    input_path = Path(input_folder).resolve()
    output_path = Path(output_folder).resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        print(f"Input not found: {input_path}")
        return

    if input_path.is_file() and input_path.suffix.lower() == ".pdf":
        pdf_files = [input_path]
    else:
        pdf_files = sorted(input_path.rglob("*.pdf"))
        pdf_files = [f for f in pdf_files if ".git" not in str(f) and "_removed" not in str(f)]

    if not pdf_files:
        print(f"No PDF files found in {input_path}")
        return

    total_techniques = 0
    processed = 0
    skipped = 0

    duplicates_skipped = 0
    seen_techniques = set()  # track by normalized title to skip duplicates

    for pdf_file in pdf_files:
        findings = process_pdf(pdf_file)

        if not findings:
            skipped += 1
            continue

        processed += 1
        rel = pdf_file.relative_to(input_path) if not input_path.is_file() else pdf_file.name
        new_count = 0

        for finding in findings:
            # Deduplicate by normalized title
            norm_title = re.sub(r"[^\w]+", " ", finding.title.lower()).strip()
            if norm_title in seen_techniques:
                duplicates_skipped += 1
                continue
            seen_techniques.add(norm_title)

            slug = re.sub(r"[^\w]+", "_", finding.title.lower())[:60].rstrip("_")
            source_hash = hashlib.sha256(
                f"{finding.source_file}:{finding.finding_id}".encode()
            ).hexdigest()[:8]
            md_filename = f"{slug}__{source_hash}.md"
            md_path = output_path / md_filename

            md_content = finding_to_markdown(finding)
            # Handle surrogate characters from broken PDF text
            md_content = md_content.encode("utf-8", errors="replace").decode("utf-8")
            md_path.write_text(md_content, encoding="utf-8")

            sev = finding.severity or "?"
            print(f"    [{sev:14s}] {finding.title[:80]}")
            new_count += 1

        total_techniques += new_count
        print(f"  Report {processed} ({rel}) — {new_count} new techniques")

    print(f"\n{'='*60}")
    print(f"Done. {total_techniques} unique techniques from {processed} reports ({skipped} skipped).")
    print(f"Duplicates skipped: {duplicates_skipped}")
    print(f"Output: {output_path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract security techniques from public pentest report PDFs."
    )
    parser.add_argument("input", help="Folder containing PDFs or a single PDF file")
    parser.add_argument("output", help="Output folder for technique .md files")
    args = parser.parse_args()
    process_folder(args.input, args.output)


if __name__ == "__main__":
    main()
