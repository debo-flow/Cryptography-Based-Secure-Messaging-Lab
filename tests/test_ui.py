"""
Automated Testing for Milestone 29: Advanced UI/UX Optimization.
Validates UI components, theme configurations, and headless Streamlit execution.
"""
import pytest
from core.ui_components import status_badge
from streamlit.testing.v1 import AppTest

def test_status_badge_colors():
    assert "#00C853" in status_badge("ACTIVE")  # Green
    assert "#D50000" in status_badge("COMPROMISED")  # Red
    assert "#FFAB00" in status_badge("PENDING")  # Yellow
    assert "#757575" in status_badge("UNKNOWN_STATE")  # Gray Fallback

def test_streamlit_app_loads_headlessly():
    """M28/M29 UI Testing: Ensures the main app layout boots without rendering errors."""
    # AppTest simulates browser interaction without opening a port
    at = AppTest.from_file("app.py", default_timeout=10)
    at.run()
    
    assert not at.exception, f"App crashed on load: {at.exception}"
    # Verify default landing page title exists
    assert any("Cryptography-Based Secure Messaging" in title.value for title in at.title)
