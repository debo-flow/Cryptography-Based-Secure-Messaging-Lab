"""
Advanced Cryptographic Performance Benchmarking Laboratory (M26).
Provides statistical rigor, CPU/Memory profiling, and concurrency analysis.
"""

import time
import statistics
import tracemalloc
import platform
import concurrent.futures
from dataclasses import dataclass
from typing import Dict, Any, List, Callable, Tuple

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

from .randomness import generate_random_bytes
from .integrity import calculate_hash
from .hmac_engine import calculate_hmac
from .aes_gcm import encrypt_aes_gcm
from .chacha20_poly1305 import encrypt_chacha20_poly1305
from .rsa import generate_rsa_key_pair
from .ed25519 import generate_ed25519_key_pair
from .exceptions import InvalidInputError

@dataclass
class BenchmarkConfig:
    algorithm: str
    operation: str
    input_size_kb: int
    iterations: int
    warmup_count: int
    concurrency_mode: str  # 'Sequential', 'Thread', 'Process'
    max_workers: int

def _get_benchmark_target(algo: str, op: str, size_kb: int) -> Tuple[Callable, Tuple, Any]:
    """Returns the callable function, arguments, and required setup state for the benchmark."""
    payload = generate_random_bytes(size_kb * 1024)
    
    if op == "Hash":
        return calculate_hash, (payload, algo), None
    elif op == "HMAC":
        key = generate_random_bytes(32)
        return calculate_hmac, (key, payload, algo), None
    elif op == "Encrypt":
        key = generate_random_bytes(32)
        if algo == "AES-256-GCM":
            return encrypt_aes_gcm, (key, payload), None
        elif algo == "ChaCha20-Poly1305":
            return encrypt_chacha20_poly1305, (key, payload), None
    elif op == "KeyGen":
        if algo == "RSA-2048":
            return generate_rsa_key_pair, (2048,), None
        elif algo == "Ed25519":
            return generate_ed25519_key_pair, (), None

    raise InvalidInputError(f"Unsupported benchmark configuration: {algo} / {op}")

def calculate_statistics(latencies: List[float]) -> Dict[str, Any]:
    """Calculates rigorous statistical metrics including percentiles and outliers."""
    if not latencies:
        return {}
        
    n = len(latencies)
    mean_lat = statistics.mean(latencies)
    median_lat = statistics.median(latencies)
    
    if n > 1:
        stdev_lat = statistics.stdev(latencies)
        variance_lat = statistics.variance(latencies)
        try:
            quantiles = statistics.quantiles(latencies, n=100)
            p90 = quantiles[89]
            p95 = quantiles[94]
            p99 = quantiles[98]
            
            # Outlier detection (IQR)
            q1, q3 = quantiles[24], quantiles[74]
            iqr = q3 - q1
            lower_bound = q1 - (1.5 * iqr)
            upper_bound = q3 + (1.5 * iqr)
            outliers = [x for x in latencies if x < lower_bound or x > upper_bound]
        except statistics.StatisticsError:
            # Fallback for very small sample sizes
            p90 = p95 = p99 = max(latencies)
            outliers = []
    else:
        stdev_lat = variance_lat = 0.0
        p90 = p95 = p99 = latencies[0]
        outliers = []

    return {
        "count": n,
        "min": min(latencies),
        "max": max(latencies),
        "mean": mean_lat,
        "median": median_lat,
        "stdev": stdev_lat,
        "variance": variance_lat,
        "p90": p90,
        "p95": p95,
        "p99": p99,
        "outlier_count": len(outliers)
    }

def run_advanced_benchmark(config: BenchmarkConfig) -> Dict[str, Any]:
    """Executes the benchmark with CPU/Memory profiling and statistical rigor."""
    
    # 1. Setup & Target Resolution
    target_fn, args, state = _get_benchmark_target(config.algorithm, config.operation, config.input_size_kb)
    
    # 2. Warm-up Phase
    for _ in range(config.warmup_count):
        target_fn(*args)
        
    latencies = []
    
    # 3. Profiling Setup
    if PSUTIL_AVAILABLE:
        psutil.cpu_percent(interval=None) # Initialize CPU counter
    tracemalloc.start()
    
    t_start_wall = time.perf_counter()
    
    # 4. Execution Phase (Sequential or Concurrent)
    if config.concurrency_mode == "Sequential" or config.max_workers <= 1:
        for _ in range(config.iterations):
            t0 = time.perf_counter()
            target_fn(*args)
            t1 = time.perf_counter()
            latencies.append(t1 - t0)
    else:
        # Note: Cryptography CFFI bindings often release the GIL, so ThreadPoolExecutor shows real speedups.
        ExecutorClass = concurrent.futures.ThreadPoolExecutor if config.concurrency_mode == "Thread" else concurrent.futures.ProcessPoolExecutor
        
        with ExecutorClass(max_workers=config.max_workers) as executor:
            futures = [executor.submit(target_fn, *args) for _ in range(config.iterations)]
            for future in concurrent.futures.as_completed(futures):
                # We measure total wall time for throughput, individual latency tracking is harder in async
                # For pure latency distributions, sequential is more accurate. 
                pass 
                
        t_end_wall = time.perf_counter()
        # For concurrent, we estimate average latency to prevent locking overhead skew
        avg_lat = (t_end_wall - t_start_wall) / config.iterations
        latencies = [avg_lat] * config.iterations

    t_end_wall = time.perf_counter()
    
    # 5. Profiling Finalization
    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    
    cpu_util = psutil.cpu_percent(interval=None) if PSUTIL_AVAILABLE else 0.0
    
    # 6. Statistical Analysis
    stats = calculate_statistics(latencies)
    total_time = t_end_wall - t_start_wall
    
    total_mb = (config.input_size_kb * config.iterations) / 1024
    throughput_mb_s = total_mb / total_time if total_time > 0 else 0
    ops_per_sec = config.iterations / total_time if total_time > 0 else 0

    return {
        "configuration": {
            "algorithm": config.algorithm,
            "operation": config.operation,
            "input_size_kb": config.input_size_kb,
            "iterations": config.iterations,
            "concurrency_mode": config.concurrency_mode,
            "max_workers": config.max_workers
        },
        "performance": {
            "total_wall_time_s": total_time,
            "ops_per_sec": ops_per_sec,
            "throughput_mb_s": throughput_mb_s,
        },
        "statistics": stats,
        "profiling": {
            "peak_memory_allocation_kb": peak_mem / 1024,
            "cpu_utilization_percent": cpu_util
        },
        "raw_latencies": latencies # Used for Plotly distributions
    }
