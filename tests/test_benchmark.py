"""
Automated Testing for Milestone 26: Advanced Cryptographic Performance Benchmarking.
Validates statistical mathematics, limits, and profiling wrappers.
"""
import pytest
from core.benchmark import BenchmarkConfig, calculate_statistics, run_advanced_benchmark
from core.exceptions import InvalidInputError

def test_statistical_calculations():
    # Known dataset
    latencies = [10.0, 10.0, 10.0, 10.0, 100.0] # 100 is a clear outlier
    stats = calculate_statistics(latencies)
    
    assert stats["count"] == 5
    assert stats["min"] == 10.0
    assert stats["max"] == 100.0
    assert stats["median"] == 10.0
    assert stats["mean"] == 28.0
    assert stats["outlier_count"] > 0
    assert stats["p99"] > 10.0

def test_benchmark_engine_execution():
    config = BenchmarkConfig(
        algorithm="SHA-256",
        operation="Hash",
        input_size_kb=1,
        iterations=5,
        warmup_count=1,
        concurrency_mode="Sequential",
        max_workers=1
    )
    
    result = run_advanced_benchmark(config)
    
    assert result["configuration"]["algorithm"] == "SHA-256"
    assert result["performance"]["ops_per_sec"] > 0
    assert "statistics" in result
    assert result["statistics"]["count"] == 5
    assert result["profiling"]["peak_memory_allocation_kb"] >= 0

def test_invalid_benchmark_configuration():
    config = BenchmarkConfig(
        algorithm="AES-256-GCM",
        operation="KeyGen", # Invalid operation for this algo
        input_size_kb=1,
        iterations=1,
        warmup_count=0,
        concurrency_mode="Sequential",
        max_workers=1
    )
    
    with pytest.raises(InvalidInputError):
        run_advanced_benchmark(config)
