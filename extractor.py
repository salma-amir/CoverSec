"""
CoverSec Technique Extractor
Extracts reusable security testing techniques from CyShield .docx
reports and outputs RAG-ready .md technique cards.

No client names, project names, or specific URLs in output —
only the technique itself, how to test for it, and standard mappings.

Usage:
    python extractor.py <input_folder> <output_folder> [--vectordb] [--service WAPT]
"""

import argparse
import hashlib
import io
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from docx import Document
from docx.oxml.ns import qn
from testcase_heuristics import get_test_cases, generalize_title

# Fix Windows console encoding for Arabic/Unicode text
if sys.platform == "win32":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ReportMeta:
    client_name: str = ""
    client_short: str = ""
    service_type: str = ""
    report_id: str = ""
    issue_date: str = ""
    template_version: str = ""
    filename: str = ""


@dataclass
class Finding:
    finding_id: str = ""
    title: str = ""
    severity: str = ""
    cvss: str = ""
    category: str = ""           # CWE
    reference: str = ""          # OWASP ref
    description: str = ""
    affected: list = field(default_factory=list)
    affected_label: str = ""
    impact: str = ""
    recommendations: list = field(default_factory=list)
    retest_status: str = ""
    is_retest_finding: bool = False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# All CyShield finding ID prefixes across all report types:
# WAPT, EIPT, SCR, WBPT — flat (Heading 1)
# MAPT → AND, iOS, API — grouped (Heading 2 under Heading 1)
# DAPT → DAPT, API — grouped
# PAPT → POS, API — grouped
# IIPT, ATMPT — flat (Heading 1)
FINDING_ID_RE = re.compile(
    r"(?:\d+\.\d+\.?\s*)?(?:R-)?"
    r"((?:R-)?(?:WAPT|EIPT|SCR|WBPT|MAPT|MAST|DAPT|PAPT|IIPT|ATMPT|API|AND|IOS|iOS|POS)\d+)"
    r"\s*:\s*(.+)",
    re.IGNORECASE,
)


def _style_name(para) -> str:
    if para.style and para.style.name:
        return para.style.name
    return ""


def _is_heading(para, level=None) -> bool:
    s = _style_name(para)
    if level is not None:
        return s == f"Heading {level}"
    return s.startswith("Heading")


def _escape_yaml(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def _iter_body_elements(doc):
    """Yield (type, element) in document order."""
    body = doc.element.body
    para_idx = 0
    table_idx = 0
    for child in body:
        if child.tag == qn("w:p"):
            if para_idx < len(doc.paragraphs):
                yield ("para", doc.paragraphs[para_idx])
            para_idx += 1
        elif child.tag == qn("w:tbl"):
            if table_idx < len(doc.tables):
                yield ("table", doc.tables[table_idx])
            table_idx += 1


# ---------------------------------------------------------------------------
# Sanitize — strip client/project-specific data from text
# ---------------------------------------------------------------------------

# Patterns to strip from descriptions and impact text
URL_RE = re.compile(r"https?://\S+")
IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b")
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")
FIGURE_RE = re.compile(r"Figure\s*\d*\s*:.*", re.IGNORECASE)
# Domain-like strings (e.g. "finwebsit.abe.com.eg")
DOMAIN_RE = re.compile(r"\b[\w-]+\.[\w-]+\.[\w.]+\b")
# File paths that look project-specific
FILE_PATH_RE = re.compile(r"[A-Za-z]:\\[\w\\.-]+|/[\w/.-]{10,}")


def _build_scrub_names(meta) -> list[str]:
    """Collect all names to scrub: client, consultants, project-specific terms."""
    names = []
    for n in [meta.client_name, meta.client_short]:
        if n and len(n) > 2:
            names.append(n)
    # Extract project/scope name from report_id (e.g. "ADIB-RTL-WAPT-TR-..." → "RTL")
    if meta.report_id:
        parts = meta.report_id.split("-")
        for part in parts:
            # Skip service type codes and generic parts
            if part.upper() in ("WAPT", "EIPT", "SCR", "WBPT", "MAPT", "MAST",
                                "TR", "TRR", "DTR", "DR", "TTR"):
                continue
            if len(part) > 3 and not part[0].isdigit():
                names.append(part)
    return names


# Product/app names that consultants embed in findings — scrub these too
PRODUCT_NAMES_RE = re.compile(
    r"\b(?:Finacle(?:\s+Core\s+Banking)?|Odoo|MinIO|Fawry|Oracle\s+E-Business\s+Suite"
    r"|IBM\s+WebSphere|Visa\s+On\s+Arrival|VOA|E-Visa)\b",
    re.IGNORECASE,
)


def _sanitize_text(text: str, scrub_names: list[str]) -> str:
    """Remove all client/project-specific info from text."""
    result = text
    # Remove URLs, IPs, emails, domains, file paths
    result = URL_RE.sub("", result)
    result = IP_RE.sub("", result)
    result = EMAIL_RE.sub("", result)
    result = FILE_PATH_RE.sub("", result)
    # Remove figure references
    result = FIGURE_RE.sub("", result)
    # Remove known product/app names
    result = PRODUCT_NAMES_RE.sub("the application", result)
    # Remove scrub names (client, project names)
    for name in scrub_names:
        if name and len(name) > 2:
            result = re.sub(r"\b" + re.escape(name) + r"\b", "", result, flags=re.IGNORECASE)
    # Clean up leftover artifacts
    result = re.sub(r"\(\s*\)", "", result)           # empty parens
    result = re.sub(r"\s{2,}", " ", result)           # double spaces
    result = re.sub(r"\n{3,}", "\n\n", result)        # triple newlines
    result = re.sub(r"^\s+", "", result, flags=re.MULTILINE)  # leading spaces on lines
    return result.strip()


def _sanitize_list(items: list[str], scrub_names: list[str]) -> list[str]:
    """Sanitize a list of strings, dropping empty/URL-only items."""
    sanitized = []
    for item in items:
        cleaned = _sanitize_text(item, scrub_names)
        if cleaned and len(cleaned) > 5:
            sanitized.append(cleaned)
    return sanitized


# ---------------------------------------------------------------------------
# Report metadata extraction (from tables)
# ---------------------------------------------------------------------------

def extract_report_meta(doc, filename: str) -> ReportMeta:
    meta = ReportMeta(filename=filename)

    fname_upper = filename.upper()
    for stype in ("WAPT", "EIPT", "SCR", "WBPT", "MAPT", "MAST", "DAPT", "PAPT", "IIPT", "ATMPT"):
        if stype in fname_upper:
            meta.service_type = stype
            break

    for table in doc.tables[:6]:
        if len(table.columns) != 2:
            continue
        for row in table.rows:
            cells = [c.text.strip() for c in row.cells]
            if len(cells) < 2:
                continue
            key, val = cells[0], cells[1]
            if not val or val.startswith("<"):
                continue
            if key == "Client Name":
                meta.client_name = val
            elif key == "Client Short Name":
                meta.client_short = val
            elif key == "Report ID":
                meta.report_id = val
            elif key == "Issue Date":
                meta.issue_date = val
            elif key == "Template Version":
                meta.template_version = val
            elif "Service" in key and "Covered" in key and not meta.service_type:
                for stype in ("WAPT", "EIPT", "SCR", "WBPT", "MAPT", "DAPT", "PAPT", "IIPT", "ATMPT"):
                    if stype in val.upper():
                        meta.service_type = stype
                        break

    if not meta.report_id:
        meta.report_id = Path(filename).stem

    return meta


# ---------------------------------------------------------------------------
# Parse finding metadata table
# ---------------------------------------------------------------------------

def _parse_finding_table(table) -> dict:
    result = {}
    for row in table.rows:
        cells = [c.text.strip() for c in row.cells]
        if not cells:
            continue
        label = cells[0].lower()
        if "severity" in label:
            for c in cells[1:]:
                if c.upper().startswith("CVSS"):
                    parts = c.split(None, 1)
                    if len(parts) > 1:
                        result["cvss"] = parts[1]
                elif c in ("Critical", "High", "Medium", "Low", "Notice", "Minimal"):
                    result["severity"] = c
        elif "category" in label:
            for c in cells[1:]:
                if c and c.upper().startswith("CWE"):
                    result["category"] = c
                    break
            if "category" not in result and len(cells) > 1 and cells[1]:
                result["category"] = cells[1]
        elif "reference" in label:
            for c in cells[1:]:
                if c:
                    result["reference"] = c
                    break
        elif "retest" in label and "status" in label:
            for c in cells[1:]:
                if c:
                    result["retest_status"] = c
                    break
    return result


def _is_finding_meta_table(table) -> bool:
    if len(table.rows) < 2 or len(table.rows) > 5:
        return False
    first_cell = table.rows[0].cells[0].text.strip().lower()
    return "severity" in first_cell


# ---------------------------------------------------------------------------
# Findings extraction
# ---------------------------------------------------------------------------

def extract_findings(doc) -> list[Finding]:
    findings: list[Finding] = []
    current: Finding | None = None
    section: str = ""
    in_findings_area = False
    in_retest_findings = False

    for etype, elem in _iter_body_elements(doc):

        if etype == "para":
            text = elem.text.strip()
            style = _style_name(elem)

            if style == "Title":
                if "Retest Findings" in text:
                    in_findings_area = True
                    in_retest_findings = True
                    continue
                elif "Findings Details" in text or "Findings" in text and "Detail" in text:
                    in_findings_area = True
                    in_retest_findings = False
                    continue
                elif "Appendices" in text or "Scope of Work" in text or "Exploitation Scenarios" in text:
                    if current:
                        findings.append(current)
                        current = None
                    in_findings_area = False
                    continue

            if not in_findings_area:
                continue
            if not text:
                continue

            # Finding headings: Heading 1 (WAPT/EIPT/SCR/WBPT) or Heading 2 (MAPT)
            if _is_heading(elem, 1) or _is_heading(elem, 2):
                m = FINDING_ID_RE.match(text)
                if m:
                    if current:
                        findings.append(current)
                    current = Finding(
                        finding_id=m.group(1).upper(),
                        title=m.group(2).strip(),
                        is_retest_finding=in_retest_findings,
                    )
                    section = ""
                elif _is_heading(elem, 1):
                    # Heading 1 without finding ID = category header (e.g. "Android Application Findings")
                    # or end of previous finding — don't reset current for MAPT categories
                    if current and not any(kw in text.lower() for kw in ("findings", "overview")):
                        findings.append(current)
                        current = None
                continue

            if current is None:
                continue

            if _is_heading(elem, 5):
                text_lower = text.lower()
                if "description" in text_lower:
                    section = "description"
                elif "affected endpoint" in text_lower:
                    section = "affected"
                    current.affected_label = "Endpoints"
                elif "affected host" in text_lower:
                    section = "affected"
                    current.affected_label = "Hosts"
                elif "affected file" in text_lower:
                    section = "affected"
                    current.affected_label = "Files"
                elif "affected" in text_lower:
                    section = "affected"
                elif "steps to reproduce" in text_lower:
                    section = "description"  # append to description
                elif "impact" in text_lower:
                    section = "impact"
                elif "recommendation" in text_lower:
                    section = "recommendations"
                elif "retest" in text_lower:
                    section = "retest_status"
                else:
                    section = ""
                continue

            if re.match(r"^\d+\.\d+\.\d+\s", text):
                continue

            if section == "description":
                if current.description:
                    current.description += "\n" + text
                else:
                    current.description = text
            elif section == "affected":
                current.affected.append(text)
            elif section == "impact":
                if current.impact:
                    current.impact += "\n" + text
                else:
                    current.impact = text
            elif section == "recommendations":
                current.recommendations.append(text)
            elif section == "retest_status":
                if current.retest_status:
                    current.retest_status += " " + text
                else:
                    current.retest_status = text

        elif etype == "table":
            if not in_findings_area or current is None:
                continue
            if section == "" and _is_finding_meta_table(elem):
                meta_dict = _parse_finding_table(elem)
                current.severity = meta_dict.get("severity", current.severity)
                current.cvss = meta_dict.get("cvss", current.cvss)
                current.category = meta_dict.get("category", current.category)
                current.reference = meta_dict.get("reference", current.reference)
                if not current.retest_status:
                    current.retest_status = meta_dict.get("retest_status", "")

    if current:
        findings.append(current)

    return findings


# ---------------------------------------------------------------------------
# Technique card — markdown output (no client data)
# ---------------------------------------------------------------------------

def technique_to_markdown(finding: Finding, meta: ReportMeta) -> str:
    """Convert a Finding into a sanitized technique card with tester-oriented test cases."""
    scrub_names = _build_scrub_names(meta)

    title = generalize_title(finding.title)
    desc = _sanitize_text(finding.description, scrub_names)
    impact = _sanitize_text(finding.impact, scrub_names)

    # Get test cases by matching technique title + CWE
    test_cases = get_test_cases(title, finding.category)

    lines = ["---"]
    lines.append(f'technique: "{_escape_yaml(title)}"')
    lines.append(f"severity: {finding.severity}")
    lines.append(f"cvss: {finding.cvss}")
    lines.append(f'cwe: "{_escape_yaml(finding.category)}"')
    lines.append(f'owasp_ref: "{_escape_yaml(finding.reference)}"')
    lines.append(f"service_type: {meta.service_type}")
    source_hash = hashlib.sha256(
        f"{meta.report_id}:{finding.finding_id}".encode()
    ).hexdigest()[:12]
    lines.append(f"source: {source_hash}")
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

    if test_cases:
        lines.append("## How to Test")
        lines.append("")
        for tc in test_cases:
            lines.append(f"- {tc}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Vector DB (optional)
# ---------------------------------------------------------------------------

def build_vectordb(md_folder: str, db_path: str):
    try:
        import chromadb
    except ImportError:
        print("ERROR: chromadb not installed. Run: pip install chromadb sentence-transformers")
        sys.exit(1)

    client = chromadb.PersistentClient(path=db_path)
    collection = client.get_or_create_collection(
        name="cyshield_techniques",
        metadata={"hnsw:space": "cosine"},
    )

    md_files = list(Path(md_folder).resolve().glob("*.md"))
    if not md_files:
        print("No .md files found to index.")
        return

    ids, documents, metadatas = [], [], []

    for f in md_files:
        content = f.read_text(encoding="utf-8")
        fm = {}
        if content.startswith("---"):
            end = content.find("---", 3)
            if end != -1:
                for line in content[3:end].strip().split("\n"):
                    if ": " in line:
                        k, v = line.split(": ", 1)
                        fm[k.strip()] = v.strip().strip('"')

        ids.append(f.stem)
        documents.append(content)
        metadatas.append({
            "technique": fm.get("technique", ""),
            "severity": fm.get("severity", ""),
            "cvss": fm.get("cvss", ""),
            "cwe": fm.get("cwe", ""),
            "owasp_ref": fm.get("owasp_ref", ""),
            "service_type": fm.get("service_type", ""),
            "source": fm.get("source", ""),
        })

    collection.upsert(ids=ids, documents=documents, metadatas=metadatas)
    print(f"Indexed {len(ids)} techniques into ChromaDB at {db_path}")


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def process_report(docx_path: Path) -> tuple[ReportMeta, list[Finding]]:
    docx_path = Path(docx_path).resolve()
    doc = Document(str(docx_path))
    meta = extract_report_meta(doc, docx_path.name)
    findings = extract_findings(doc)
    return meta, findings


def process_folder(
    input_folder: str,
    output_folder: str,
    vectordb: bool = False,
    service_filter: str | None = None,
):
    input_path = Path(input_folder).resolve()
    output_path = Path(output_folder).resolve()
    output_path.mkdir(parents=True, exist_ok=True)

    if not input_path.exists():
        print(f"Input not found: {input_path}")
        return

    # Support both single file and folder as input
    if input_path.is_file() and input_path.suffix == ".docx":
        docx_files = [input_path]
    else:
        docx_files = sorted([
            f for f in input_path.glob("*.docx")
            if not f.name.startswith("~$")
        ])

    if not docx_files:
        print(f"No .docx files found in {input_path}")
        return

    total_techniques = 0
    duplicates_skipped = 0
    processed_reports = 0
    seen_techniques = set()  # track by normalized title to skip duplicates

    for docx_file in docx_files:
        if not docx_file.exists():
            print(f"  SKIP [file not found]: {docx_file.name}")
            continue
        try:
            meta, findings = process_report(docx_file)
        except Exception as e:
            print(f"  ERROR [report skipped]: {e}")
            continue

        # Filter by service type
        if service_filter and meta.service_type != service_filter.upper():
            continue

        # Skip non-report docs (0 findings)
        if not findings:
            continue

        processed_reports += 1
        new_count = 0

        for finding in findings:
            # Deduplicate by normalized title
            norm_title = re.sub(r"[^\w]+", " ", finding.title.lower()).strip()
            if norm_title in seen_techniques:
                duplicates_skipped += 1
                continue
            seen_techniques.add(norm_title)

            # Filename: hash-based to avoid client info in filenames
            slug = re.sub(r"[^\w]+", "_", finding.title.lower())[:60].rstrip("_")
            source_hash = hashlib.sha256(
                f"{meta.report_id}:{finding.finding_id}".encode()
            ).hexdigest()[:8]
            md_filename = f"{slug}__{source_hash}.md"
            md_path = output_path / md_filename

            md_content = technique_to_markdown(finding, meta)
            md_path.write_text(md_content, encoding="utf-8")

            sev = finding.severity or "?"
            print(f"    [{sev:8s}] {finding.title}")
            new_count += 1

        total_techniques += new_count
        print(f"\n  [{meta.service_type}] Report {processed_reports} — {new_count} new techniques")

    print(f"\n{'='*60}")
    svc_label = f" ({service_filter.upper()})" if service_filter else ""
    print(f"Done. {total_techniques} unique techniques from {processed_reports} reports{svc_label}.")
    print(f"Duplicates skipped: {duplicates_skipped}")
    print(f"Output: {output_path.resolve()}")

    if vectordb:
        db_path = str(output_path / "chromadb")
        build_vectordb(str(output_path), db_path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Extract security techniques from CyShield reports into RAG-ready .md files."
    )
    parser.add_argument("input", help="Folder containing .docx reports, or a single .docx file")
    parser.add_argument("output", help="Output folder for technique .md files")
    parser.add_argument(
        "--service", default=None,
        help="Filter by service type: WAPT, EIPT, SCR, WBPT, MAPT, DAPT, PAPT, IIPT, ATMPT",
    )
    parser.add_argument(
        "--vectordb", action="store_true",
        help="Also build a ChromaDB vector store from the extracted techniques",
    )
    args = parser.parse_args()
    process_folder(args.input, args.output, vectordb=args.vectordb, service_filter=args.service)


if __name__ == "__main__":
    main()
