#!/usr/bin/env python3
"""
Montana VDF Benchmark v3.7

Measures Class Group VDF performance for timing analysis.
Results validate whitepaper claims about VDF timing.

VDF: Class Group (Wesolowski 2019), Type B security.
"""

import time
import platform
import statistics
from dataclasses import dataclass
from typing import List, Tuple

# Import Montana VDF
import sys
sys.path.insert(0, '..')

try:
    from montana.core.vdf import ClassGroupVDF, VDFOutput
    MONTANA_AVAILABLE = True
except ImportError:
    MONTANA_AVAILABLE = False


@dataclass
class BenchmarkResult:
    iterations: int
    total_time_sec: float
    time_per_iteration_ns: float
    iterations_per_sec: float


def benchmark_class_group_vdf(iterations: int, runs: int = 3) -> BenchmarkResult:
    """Benchmark Class Group VDF computation."""
    if not MONTANA_AVAILABLE:
        raise RuntimeError("Montana VDF not available")

    vdf = ClassGroupVDF(iterations=iterations)
    times = []
    input_data = b'\x00' * 32

    for _ in range(runs):
        start = time.perf_counter()
        result = vdf.compute(input_data)
        elapsed = time.perf_counter() - start
        times.append(elapsed)

    avg_time = statistics.mean(times)

    return BenchmarkResult(
        iterations=iterations,
        total_time_sec=avg_time,
        time_per_iteration_ns=(avg_time / iterations) * 1e9,
        iterations_per_sec=iterations / avg_time,
    )


def main():
    print("=" * 60)
    print("Montana VDF Benchmark v3.7")
    print("VDF: Class Group (Wesolowski 2019)")
    print("=" * 60)

    # System info
    print(f"\nPlatform: {platform.platform()}")
    print(f"Python: {platform.python_version()}")
    print(f"Processor: {platform.processor() or 'N/A'}")

    if not MONTANA_AVAILABLE:
        print("\nERROR: Montana VDF not available")
        print("Run from Montana directory or install montana package")
        return

    # VDF benchmarks at various iteration counts
    print("\n" + "-" * 60)
    print("Class Group VDF Benchmark")
    print("-" * 60)

    # Smaller iterations for benchmarking (full 2^24 takes too long)
    test_iterations = [
        1_000,
        10_000,
        100_000,
    ]

    results = []
    for iters in test_iterations:
        print(f"\nBenchmarking {iters:,} iterations...", end=" ", flush=True)
        try:
            result = benchmark_class_group_vdf(iters, runs=3)
            results.append(result)
            print(f"{result.total_time_sec:.3f}s")
        except Exception as e:
            print(f"Error: {e}")

    if not results:
        print("\nNo results collected")
        return

    # Results table
    print("\n" + "=" * 60)
    print("Results Summary")
    print("=" * 60)
    print(f"{'Iterations':<15} {'Time (sec)':<12} {'ns/iter':<12} {'iter/sec':<15}")
    print("-" * 60)

    for r in results:
        print(f"{r.iterations:<15,} {r.total_time_sec:<12.4f} {r.time_per_iteration_ns:<12.1f} {r.iterations_per_sec:<15,.0f}")

    # Extrapolate to 2^24
    print("\n" + "-" * 60)
    print("Extrapolation to Montana VDF Parameters")
    print("-" * 60)

    # Use the most accurate measurement (longest run)
    best_result = results[-1]
    ns_per_iter = best_result.time_per_iteration_ns

    vdf_iterations = 2**24  # 16,777,216
    estimated_time = (vdf_iterations * ns_per_iter) / 1e9

    print(f"\nVDF_BASE_ITERATIONS = 2^24 = {vdf_iterations:,}")
    print(f"Estimated time per VDF: {estimated_time:.2f} seconds")
    print(f"Time per iteration: {ns_per_iter:.1f} ns")

    # UTC finality model
    print("\n" + "-" * 60)
    print("UTC Finality Model")
    print("-" * 60)
    print("VDF proves participation eligibility, not speed.")
    print("All nodes bounded by UTC minute boundaries.")
    print(f"Estimated VDF time: {estimated_time:.2f} seconds")
    print(f"Waiting time: {60 - estimated_time:.2f} seconds")
    print("Result: 1 heartbeat per minute (regardless of hardware)")

    # Security
    print("\n" + "-" * 60)
    print("Security Properties")
    print("-" * 60)
    print("Type: B (reduction to class group order problem)")
    print("Trusted setup: None required")
    print("Verification: O(log T) using Wesolowski proof")
    print("Quantum: Shor applies, but UTC model neutralizes speedup")

    print("\n" + "=" * 60)
    print("Benchmark Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
