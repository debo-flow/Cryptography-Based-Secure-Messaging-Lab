"""
Automated Testing & Validation for Milestone 1.
Tests application configuration, roadmap integrity, and core utilities.
"""

import pytest
from config import ROADMAP, NAVIGATION, TOTAL_MILESTONES
from utils import error_handler

def test_roadmap_integrity():
    """Test that exactly 35 milestones are defined and structured correctly."""
    assert len(ROADMAP) == 35, f"Expected 35 milestones, found {len(ROADMAP)}"
    assert TOTAL_MILESTONES == 35
    
    # Check that M01 is completed and M35 is pending
    assert ROADMAP[0]["id"] == "M01"
    assert ROADMAP[0]["status"] == "Completed"
    
    assert ROADMAP[-1]["id"] == "M35"
    assert ROADMAP[-1]["status"] == "Pending"

def test_navigation_configuration():
    """Test that all required navigation items are present."""
    expected_nav = [
        "Dashboard", "Encryption Laboratory", "AES Encryption", "RSA Encryption",
        "ChaCha20 Encryption", "Fernet Encryption", "Hybrid Encryption",
        "Public-Key Cryptography", "Password-Based Encryption", "End-to-End Messaging",
        "Digital Signatures", "Secure File Encryption", "Key Management",
        "Message Authentication", "Algorithm Comparison", "Performance Benchmark",
        "Security Analysis", "Project Roadmap", "About Project"
    ]
    
    assert len(NAVIGATION) == len(expected_nav)
    for expected_item in expected_nav:
        assert expected_item in NAVIGATION, f"Missing navigation item: {expected_item}"

def test_error_handler_utility():
    """Test that the centralized error handler catches exceptions without breaking execution."""
    
    @error_handler
    def unstable_function():
        raise ValueError("Simulated failure")
        return True

    # The decorator should catch the ValueError and return None implicitly
    # instead of raising the exception to the caller.
    result = unstable_function()
    assert result is None
