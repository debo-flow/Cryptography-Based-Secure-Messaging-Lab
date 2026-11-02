"""
Automated Testing for Milestone 1: Foundation & Architecture.
"""
import pytest
from config import ROADMAP, NAVIGATION, TOTAL_MILESTONES

def test_roadmap_integrity():
    assert len(ROADMAP) == 35
    assert TOTAL_MILESTONES == 35
    assert ROADMAP[0]["id"] == "M01"
    assert ROADMAP[0]["status"] == "Completed"
    assert ROADMAP[1]["id"] == "M02"
    assert ROADMAP[1]["status"] == "Completed"
    assert ROADMAP[-1]["id"] == "M35"
    assert ROADMAP[-1]["status"] == "Pending"

def test_navigation_configuration():
    assert "Cryptographic Core Engine" in NAVIGATION
    assert "Dashboard" in NAVIGATION
