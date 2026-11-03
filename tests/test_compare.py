"""
Automated Testing for Milestone 25: Algorithm Comparison & Benchmarking Engine.
Validates stat generation, registry access, and report rendering formats.
"""
import pytest
from core.compare import (
    SECURITY_PROPERTIES, get_algorithm_recommendations, get_environment_info,
    benchmark_symmetric, benchmark_signatures, generate_csv_report
)

def test_security_registry_integrity():
    assert "AES-256-GCM" in SECURITY_PROPERTIES
    assert "Ed25519" in SECURITY_PROPERTIES
    assert SECURITY_PROPERTIES["AES-256-GCM"]["Type"] == "Symmetric AEAD"
    assert SECURITY_PROPERTIES["Ed25519"]["Confidentiality"] == "No" # Signatures don't encrypt

def test_recommendation_engine():
    rec = get_algorithm_recommendations("Secure Messaging (E2EE)")
    assert "X25519" in rec["Recommendation"]
    assert "Ed25519" in rec["Recommendation"]
    
    rec_unk = get_algorithm_recommendations("Invalid Use Case")
    assert rec_unk["Recommendation"] == "Unknown"

def test_environment_info():
    env = get_environment_info()
    assert "OS" in env
    assert "Python Version" in env
    assert "Timestamp" in env

def test_symmetric_benchmarking_logic():
    # Use extremely small payload and 1 iteration to keep test fast
    results = benchmark_symmetric("AES-256-GCM", payload_sizes_kb=[1], iterations=1)
    
    assert len(results) == 1
    res = results[0]
    assert res["Algorithm"] == "AES-256-GCM"
    assert "Throughput (MB/s)" in res
    assert res["Mean Encrypt (ms)"] >= 0

def test_csv_report_generation():
    env = get_environment_info()
    sym = [{"Algo": "Test", "Latency": 10}]
    sig = [{"Algo": "TestSig", "Latency": 20}]
    
    csv_out = generate_csv_report(env, sym, sig)
    assert "### ENVIRONMENT METADATA ###" in csv_out
    assert "TestSig" in csv_out
