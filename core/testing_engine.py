"""
Advanced Automated Testing Framework (M28).
Provides an isolated execution environment to run Pytest, Hypothesis, and Coverage 
programmatically from the Streamlit UI, returning sanitized JSON reports.
"""

import subprocess
import json
import os
import io
import csv
from typing import Dict, Any, List
from datetime import datetime, timezone

try:
    from fpdf import FPDF
    FPDF_AVAILABLE = True
except ImportError:
    FPDF_AVAILABLE = False

from .exceptions import CryptographicOperationError

def run_automated_test_suite(target: str = "tests/") -> Dict[str, Any]:
    """
    Executes pytest in a controlled subprocess using pytest-json-report.
    Captures metrics, coverage, and failures securely.
    """
    report_file = "test_report.json"
    
    # Ensure no old reports interfere
    if os.path.exists(report_file):
        os.remove(report_file)

    try:
        # Run Pytest with JSON reporting and Coverage
        # subprocess run blocks until tests complete (simulating a CI pipeline run)
        result = subprocess.run(
            ["pytest", target, "--json-report", f"--json-report-file={report_file}", "--cov=core", "--disable-warnings"],
            capture_output=True,
            text=True
        )
        
        # Pytest returns 0 for all passed, 1 for some failed, 5 for no tests collected
        if result.returncode not in [0, 1]:
            raise CryptographicOperationError(f"Test framework execution failed: {result.stderr}")
            
        if not os.path.exists(report_file):
            raise CryptographicOperationError("Test report was not generated.")
            
        with open(report_file, "r") as f:
            report_data = json.load(f)
            
        # Clean up temporary report file
        os.remove(report_file)
        
        return report_data

    except Exception as e:
        raise CryptographicOperationError(f"Test Execution Engine Error: {str(e)}")

def generate_test_report_csv(report_data: Dict[str, Any]) -> str:
    """Safely flattens the JSON test report into a CSV audit trail."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Test Node ID", "Outcome", "Duration (s)", "Setup Outcome"])
    
    for test in report_data.get("tests", []):
        writer.writerow([
            test.get("nodeid", "Unknown"),
            test.get("outcome", "Unknown"),
            round(test.get("setup", {}).get("duration", 0) + test.get("call", {}).get("duration", 0), 4),
            test.get("setup", {}).get("outcome", "Unknown")
        ])
    return output.getvalue()

def generate_test_report_pdf(report_data: Dict[str, Any]) -> bytes:
    """Generates a sanitized PDF executive summary of the test execution."""
    if not FPDF_AVAILABLE:
        raise CryptographicOperationError("fpdf2 library not installed.")
        
    summary = report_data.get("summary", {})
    
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    pdf.cell(200, 10, txt="Automated Cryptographic Validation Report (M28)", ln=True, align='C')
    pdf.ln(10)
    
    pdf.set_font("Arial", style='B', size=10)
    pdf.cell(200, 10, txt=f"Execution Timestamp: {datetime.now(timezone.utc).isoformat()}", ln=True)
    pdf.cell(200, 10, txt=f"Total Tests Executed: {summary.get('total', 0)}", ln=True)
    pdf.cell(200, 10, txt=f"Tests Passed: {summary.get('passed', 0)}", ln=True)
    pdf.cell(200, 10, txt=f"Tests Failed: {summary.get('failed', 0)}", ln=True)
    pdf.cell(200, 10, txt=f"Total Duration: {round(report_data.get('duration', 0), 2)} seconds", ln=True)
    
    pdf.ln(5)
    pdf.set_font("Arial", style='B', size=10)
    pdf.cell(200, 10, txt="Failed Test Details:", ln=True)
    pdf.set_font("Arial", size=9)
    
    failures = [t for t in report_data.get("tests", []) if t.get("outcome") == "failed"]
    if not failures:
        pdf.cell(200, 6, txt="ZERO FAILURES DETECTED. ALL CRYPTOGRAPHIC INVARIANTS HOLD.", ln=True)
    else:
        for f in failures:
            pdf.cell(200, 6, txt=f"FAILED: {f.get('nodeid')}", ln=True)
            
    return bytes(pdf.output(dest='S'))
