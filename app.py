"""
app.py
Streamlit Web Application for Serverless Function Security Auditor.
Provides an interactive web dashboard for static security analysis of
serverless functions (AWS Lambda, Azure Functions) and IAM configurations.

SECURITY GUARANTEE:
Uploaded code is strictly parsed via offline Abstract Syntax Tree (AST) analysis
and regular expressions. Uploaded files are NEVER executed or imported.
"""

import os
import sys
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import List, Tuple

import streamlit as st

# Import existing scanner models and orchestrator
from models.finding import Finding, Severity
from scanner import AuditorCLI


# -----------------------------------------------------------------------------
# Streamlit Page Configuration
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="Serverless Function Security Auditor",
    page_icon="⚡",
    layout="wide",
    initial_sidebar_state="expanded"
)


# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------
def get_severity_badge(severity: Severity) -> str:
    """Return a color-coded Markdown badge for finding severity."""
    badges = {
        Severity.CRITICAL: "🔴 **CRITICAL**",
        Severity.HIGH: "🟠 **HIGH**",
        Severity.MEDIUM: "🟡 **MEDIUM**",
        Severity.LOW: "🔵 **LOW**",
    }
    return badges.get(severity, f"⚪ **{severity.value}**")


def safe_extract_zip(uploaded_zip, target_dir: Path) -> List[Path]:
    """
    Safely extract an uploaded ZIP file, defending against Zip Slip path traversal.
    Returns list of extracted file paths.
    """
    extracted_paths: List[Path] = []
    with zipfile.ZipFile(uploaded_zip, "r") as z:
        for member in z.infolist():
            # Defense against Zip Slip (CVE-2018-1002200): Disallow relative traversal
            member_path = Path(member.filename)
            if member_path.is_absolute() or ".." in member_path.parts:
                continue

            destination = (target_dir / member_path).resolve()
            if not destination.is_relative_to(target_dir.resolve()):
                continue

            z.extract(member, target_dir)
            if destination.is_file():
                extracted_paths.append(destination)
    return extracted_paths


def audit_directory(dir_path: Path, display_root: Path = None) -> Tuple[List[Finding], List[str]]:
    """
    Run the existing AuditorCLI against a target directory.
    Cleans up file paths for relative presentation.
    """
    cli = AuditorCLI(target_path=dir_path)
    raw_files = cli.collect_files()
    findings = cli.run_scan()

    # Normalize file paths for clean display
    root = display_root or dir_path
    relative_files = []
    for f in raw_files:
        try:
            rel = f.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            rel = f.name
        relative_files.append(rel)

    for finding in findings:
        try:
            finding.file = Path(finding.file).resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            finding.file = Path(finding.file).name

    return findings, relative_files


# -----------------------------------------------------------------------------
# Main Application UI
# -----------------------------------------------------------------------------
def main():
    # Header Section
    st.title("⚡ Serverless Function Security Auditor")
    st.markdown(
        "**Static security analysis for serverless functions and configuration.**  \n"
        "Inspects Python handlers and AWS IAM policies for hardcoded credentials, "
        "excessive permissions, and command/SQL injection flows."
    )

    # Security Disclaimer Callout
    st.info(
        "🔒 **Defensive Security Notice:** Uploaded files are evaluated strictly through static Abstract Syntax Tree (AST) "
        "inspection and pattern matching. Uploaded code is **NEVER executed or deployed**.",
        icon="ℹ️"
    )

    st.divider()

    # Sidebar: Audit Selection & Settings
    st.sidebar.header("Audit Configuration")
    audit_mode = st.sidebar.radio(
        "Select Scan Target:",
        options=["Demo Serverless Project", "Upload Project ZIP"],
        index=0
    )

    severity_filter = st.sidebar.selectbox(
        "Filter by Severity:",
        options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
        index=0
    )

    st.sidebar.markdown("---")
    st.sidebar.markdown(
        "### About this Auditor\n"
        "- **Phase 1**: Secrets (`AKIA...`, passwords, tokens) & IAM Policy Wildcards.\n"
        "- **Phase 2**: Python AST Analysis, Event Sources, SQLi, and Command Injection.\n"
        "- **Engine**: Python 3.11+ Standard Library (`ast`, `re`, `json`)."
    )

    # Initialize Session State
    if "findings" not in st.session_state:
        st.session_state.findings = None
        st.session_state.scanned_files = None
        st.session_state.target_name = None

    # Audit Trigger Sections
    if audit_mode == "Demo Serverless Project":
        st.subheader("📁 Built-in Demo Suite")
        st.markdown(
            "Audit the repository's built-in demo serverless functions:  \n"
            "- `demo/vulnerable_function.py`: Hardcoded test credentials and tokens.  \n"
            "- `demo/injection_function.py`: Command & SQL injection patterns.  \n"
            "- `demo/policy.json`: Broad wildcard AWS IAM statements.  \n"
            "- `demo/safe_function.py`: Best-practice secure Lambda handler."
        )

        if st.button("🚀 Run Demo Security Audit", type="primary"):
            demo_path = Path("demo")
            if not demo_path.exists():
                st.error("Error: 'demo' directory not found in the project root.")
            else:
                with st.spinner("Analyzing demo files with AST and IAM scanners..."):
                    try:
                        findings, files = audit_directory(demo_path)
                        st.session_state.findings = findings
                        st.session_state.scanned_files = files
                        st.session_state.target_name = "demo"
                        st.success(f"Audit completed! Discovered {len(findings)} findings across {len(files)} files.")
                    except Exception as e:
                        st.error(f"Scanner exception occurred: {str(e)}")

    else:
        st.subheader("📦 Upload Serverless Project")
        st.markdown("Upload a `.zip` archive containing your serverless functions (`.py`, `.js`, `.ts`) or IAM policies (`.json`).")

        uploaded_file = st.file_uploader(
            "Choose a ZIP file",
            type=["zip"],
            help="Zip archive containing your serverless project source code and configuration files."
        )

        if uploaded_file is not None:
            if st.button("🔍 Scan Uploaded Archive", type="primary"):
                with st.spinner("Extracting and analyzing project statically..."):
                    temp_dir = tempfile.mkdtemp(prefix="serverless_audit_")
                    temp_path = Path(temp_dir)
                    try:
                        extracted = safe_extract_zip(uploaded_file, temp_path)
                        if not extracted:
                            st.warning("The uploaded archive was empty or contained no valid files.")
                        else:
                            findings, files = audit_directory(temp_path)
                            st.session_state.findings = findings
                            st.session_state.scanned_files = files
                            st.session_state.target_name = uploaded_file.name
                            st.success(f"Audit completed for **{uploaded_file.name}**! {len(findings)} findings across {len(files)} files.")
                    except zipfile.BadZipFile:
                        st.error("Error: The uploaded file is not a valid or readable ZIP archive.")
                    except Exception as e:
                        st.error(f"Scanner error during analysis: {str(e)}")
                    finally:
                        # Clean up temporary extracted files
                        shutil.rmtree(temp_dir, ignore_errors=True)

    # -------------------------------------------------------------------------
    # Display Results Dashboard
    # -------------------------------------------------------------------------
    if st.session_state.findings is not None:
        findings: List[Finding] = st.session_state.findings
        scanned_files: List[str] = st.session_state.scanned_files or []

        st.markdown("---")
        st.header(f"Security Results — {st.session_state.target_name}")

        # Summary Metrics
        crit_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        med_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)
        total_count = len(findings)

        col1, col2, col3, col4, col5 = st.columns(5)
        col1.metric("🔴 Critical", crit_count)
        col2.metric("🟠 High", high_count)
        col3.metric("🟡 Medium", med_count)
        col4.metric("🔵 Low", low_count)
        col5.metric("📊 Total Findings", total_count)

        # Apply Severity Filter
        if severity_filter != "All":
            filtered_findings = [f for f in findings if f.severity.value == severity_filter]
        else:
            filtered_findings = findings

        # Findings Explorer
        st.subheader(f"Findings ({len(filtered_findings)} displayed)")
        if not filtered_findings:
            if total_count == 0:
                st.success("🎉 Excellent! No security vulnerabilities or misconfigurations detected.")
            else:
                st.info(f"No findings matching severity filter '{severity_filter}'.")
        else:
            for f in filtered_findings:
                badge = get_severity_badge(f.severity)
                loc_str = f"**File:** `{f.file}`"
                if f.line is not None:
                    loc_str += f" | **Line:** `{f.line}`"
                if f.statement_id is not None:
                    loc_str += f" | **Statement:** `{f.statement_id}`"

                with st.expander(f"{badge} [{f.id}] {f.title}"):
                    st.markdown(f"**Type:** `{f.type}`")
                    st.markdown(loc_str)
                    st.markdown(f"**Description:**  \n{f.description}")
                    st.info(f"💡 **Recommendation:**  \n{f.recommendation}")

        # Security Recommendations Summary Section
        st.markdown("---")
        st.subheader("💡 Key Security Recommendations")
        unique_recs = []
        for f in findings:
            if f.recommendation and f.recommendation not in unique_recs:
                unique_recs.append(f.recommendation)

        if unique_recs:
            for idx, rec in enumerate(unique_recs, start=1):
                st.markdown(f"**{idx}.** {rec}")
        else:
            st.markdown("✓ All audited functions and policies currently comply with least-privilege standards.")

        # Scanned Files Section
        st.markdown("---")
        st.subheader(f"📂 Scanned Files ({len(scanned_files)})")
        if scanned_files:
            with st.expander("View list of analyzed project files"):
                for sf in scanned_files:
                    st.markdown(f"- `{sf}`")
        else:
            st.text("No supported source files discovered in target.")


if __name__ == "__main__":
    main()
