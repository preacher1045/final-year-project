#!/usr/bin/env python3
"""
Generate baseline profiles from collected metrics.

This script reads the metrics JSONL file and generates baseline reference data
that can be used for anomaly detection. Baselines include:

1. Normal traffic profiles: mean, median, and percentile statistics
2. Rolling averages: time-windowed moving averages for key metrics
3. Protocol distributions and flow characteristics
4. Bandwidth and latency patterns

The baselines are stored as JSON files in app/baselines/ for reference during
real-time monitoring and anomaly detection.
"""

import json
import os
from typing import Dict, List, Any
from statistics import mean, median


def load_metrics(metrics_file: str) -> List[Dict[str, Any]]:
    """Load all metric windows from JSONL file."""
    records = []
    if not os.path.exists(metrics_file):
        print(f"Warning: Metrics file {metrics_file} not found")
        return records
    
    with open(metrics_file, 'r') as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    
    print(f"Loaded {len(records)} metric windows")
    return records


def compute_rolling_average(values: List[float], window_size: int = 3) -> Dict[str, float]:
    """
    Compute rolling averages with specified window size.
    Returns mean, median, min, max of the rolling averages.
    """
    if not values or len(values) < window_size:
        return {}
    
    rolling_avgs = []
    for i in range(len(values) - window_size + 1):
        window = values[i:i + window_size]
        rolling_avgs.append(mean(window))
    
    return {
        "rolling_avg_mean": round(mean(rolling_avgs), 4),
        "rolling_avg_median": round(median(rolling_avgs), 4),
        "rolling_avg_min": round(min(rolling_avgs), 4),
        "rolling_avg_max": round(max(rolling_avgs), 4),
    }


def generate_bandwidth_baseline(metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate bandwidth baseline: normal profile and rolling averages.
    Includes per-window bandwidth stats and trends.
    """
    baseline = {
        "metric_type": "bandwidth",
        "description": "Bandwidth patterns for normal traffic",
        "window_count": len(metrics)
    }
    
    # Extract bandwidth metrics per window
    bps_values = [
        m.get("bandwidth", {}).get("avg_bps", 0) 
        for m in metrics 
        if m.get("bandwidth", {}).get("avg_bps") is not None
    ]
    
    pps_values = [
        m.get("bandwidth", {}).get("avg_pps", 0) 
        for m in metrics 
        if m.get("bandwidth", {}).get("avg_pps") is not None
    ]
    
    total_bytes_values = [
        m.get("bandwidth", {}).get("total_bytes", 0) 
        for m in metrics 
        if "bandwidth" in m
    ]
    
    total_pkt_values = [
        m.get("bandwidth", {}).get("total_packets", 0) 
        for m in metrics 
        if "bandwidth" in m
    ]
    
    if bps_values:
        baseline["bytes_per_second"] = {
            "mean": round(mean(bps_values), 2),
            "median": round(median(bps_values), 2),
            "min": round(min(bps_values), 2),
            "max": round(max(bps_values), 2),
            "p90": round(sorted(bps_values)[int(len(bps_values) * 0.9)], 2),
            "p99": round(sorted(bps_values)[int(len(bps_values) * 0.99)], 2) if len(bps_values) > 1 else round(bps_values[0], 2),
        }
        baseline["bytes_per_second"].update(compute_rolling_average(bps_values))
    
    if pps_values:
        baseline["packets_per_second"] = {
            "mean": round(mean(pps_values), 2),
            "median": round(median(pps_values), 2),
            "min": round(min(pps_values), 2),
            "max": round(max(pps_values), 2),
            "p90": round(sorted(pps_values)[int(len(pps_values) * 0.9)], 2),
            "p99": round(sorted(pps_values)[int(len(pps_values) * 0.99)], 2) if len(pps_values) > 1 else round(pps_values[0], 2),
        }
        baseline["packets_per_second"].update(compute_rolling_average(pps_values))
    
    if total_bytes_values:
        baseline["bytes_per_window"] = {
            "mean": round(mean(total_bytes_values), 0),
            "median": round(median(total_bytes_values), 0),
            "min": round(min(total_bytes_values), 0),
            "max": round(max(total_bytes_values), 0),
        }
    
    if total_pkt_values:
        baseline["packets_per_window"] = {
            "mean": round(mean(total_pkt_values), 0),
            "median": round(median(total_pkt_values), 0),
            "min": round(min(total_pkt_values), 0),
            "max": round(max(total_pkt_values), 0),
        }
    
    return baseline


def generate_latency_baseline(metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate latency baseline: TCP RTT and request-response patterns.
    Includes rolling averages for trend detection.
    """
    baseline = {
        "metric_type": "latency",
        "description": "Latency patterns for normal traffic",
        "window_count": len(metrics)
    }
    
    # Extract TCP RTT values
    tcp_rtt_values = [
        m.get("latency", {}).get("tcp_rtt", {}).get("mean", 0)
        for m in metrics 
        if m.get("latency", {}).get("tcp_rtt", {}).get("mean") is not None
        and m.get("latency", {}).get("tcp_rtt", {}).get("count", 0) > 0
    ]
    
    # Extract request-response latencies
    req_resp_values = [
        m.get("latency", {}).get("request_response", {}).get("mean", 0)
        for m in metrics 
        if m.get("latency", {}).get("request_response", {}).get("mean") is not None
        and m.get("latency", {}).get("request_response", {}).get("count", 0) > 0
    ]
    
    if tcp_rtt_values:
        baseline["tcp_rtt_ms"] = {
            "mean": round(mean(tcp_rtt_values) * 1000, 2),
            "median": round(median(tcp_rtt_values) * 1000, 2),
            "min": round(min(tcp_rtt_values) * 1000, 2),
            "max": round(max(tcp_rtt_values) * 1000, 2),
            "p90": round(sorted(tcp_rtt_values)[int(len(tcp_rtt_values) * 0.9)] * 1000, 2),
            "p99": round(sorted(tcp_rtt_values)[int(len(tcp_rtt_values) * 0.99)] * 1000, 2) if len(tcp_rtt_values) > 1 else round(tcp_rtt_values[0] * 1000, 2),
        }
        baseline["tcp_rtt_ms"].update(compute_rolling_average([v * 1000 for v in tcp_rtt_values]))
    
    if req_resp_values:
        baseline["request_response_ms"] = {
            "mean": round(mean(req_resp_values) * 1000, 2),
            "median": round(median(req_resp_values) * 1000, 2),
            "min": round(min(req_resp_values) * 1000, 2),
            "max": round(max(req_resp_values) * 1000, 2),
            "p90": round(sorted(req_resp_values)[int(len(req_resp_values) * 0.9)] * 1000, 2),
            "p99": round(sorted(req_resp_values)[int(len(req_resp_values) * 0.99)] * 1000, 2) if len(req_resp_values) > 1 else round(req_resp_values[0] * 1000, 2),
        }
        baseline["request_response_ms"].update(compute_rolling_average([v * 1000 for v in req_resp_values]))
    
    return baseline


def generate_protocol_baseline(metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate protocol distribution baseline: typical protocol mix and trends.
    """
    baseline = {
        "metric_type": "protocol",
        "description": "Protocol distribution patterns",
        "window_count": len(metrics)
    }
    
    # Aggregate protocol distributions across all windows
    protocol_counts = {}
    total_packets = 0
    
    for m in metrics:
        proto_data = m.get("protocol", {})
        counts = proto_data.get("counts", {})
        
        for proto_id, count in counts.items():
            protocol_counts[proto_id] = protocol_counts.get(proto_id, 0) + count
            total_packets += count
    
    if total_packets > 0:
        # Compute percentages
        baseline["protocol_distribution"] = {
            str(proto_id): {
                "count": count,
                "percentage": round(100.0 * count / total_packets, 2)
            }
            for proto_id, count in sorted(
                protocol_counts.items(), 
                key=lambda x: x[1], 
                reverse=True
            )
        }
        baseline["total_packets_analyzed"] = total_packets
    
    return baseline


def generate_connection_baseline(metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate connection statistics baseline: typical connection patterns.
    """
    baseline = {
        "metric_type": "connection",
        "description": "Connection characteristics for normal traffic",
        "window_count": len(metrics)
    }
    
    # Extract connection metrics
    attempts = [
        m.get("connections", {}).get("total_attempts", 0)
        for m in metrics if "connections" in m
    ]
    
    successful = [
        m.get("connections", {}).get("successful", 0)
        for m in metrics if "connections" in m
    ]
    
    failed = [
        m.get("connections", {}).get("failed_resets", 0)
        for m in metrics if "connections" in m
    ]
    
    duration = [
        m.get("connections", {}).get("avg_duration_s", 0)
        for m in metrics 
        if m.get("connections", {}).get("avg_duration_s") is not None
        and m.get("connections", {}).get("avg_duration_s", 0) > 0
    ]
    
    bytes_per_conn = [
        m.get("connections", {}).get("avg_bytes_per_conn", 0)
        for m in metrics 
        if m.get("connections", {}).get("avg_bytes_per_conn") is not None
        and m.get("connections", {}).get("avg_bytes_per_conn", 0) > 0
    ]
    
    if attempts:
        baseline["connection_attempts"] = {
            "mean": round(mean(attempts), 2),
            "median": round(median(attempts), 2),
            "min": round(min(attempts), 2),
            "max": round(max(attempts), 2),
        }
    
    if successful:
        baseline["successful_connections"] = {
            "mean": round(mean(successful), 2),
            "median": round(median(successful), 2),
            "min": round(min(successful), 2),
            "max": round(max(successful), 2),
        }
    
    if failed:
        baseline["failed_connections"] = {
            "mean": round(mean(failed), 2),
            "median": round(median(failed), 2),
            "min": round(min(failed), 2),
            "max": round(max(failed), 2),
        }
    
    if duration:
        baseline["connection_duration_s"] = {
            "mean": round(mean(duration), 4),
            "median": round(median(duration), 4),
            "min": round(min(duration), 4),
            "max": round(max(duration), 4),
        }
        baseline["connection_duration_s"].update(compute_rolling_average(duration))
    
    if bytes_per_conn:
        baseline["bytes_per_connection"] = {
            "mean": round(mean(bytes_per_conn), 2),
            "median": round(median(bytes_per_conn), 2),
            "min": round(min(bytes_per_conn), 2),
            "max": round(max(bytes_per_conn), 2),
        }
    
    return baseline


def save_baseline(baseline: Dict[str, Any], output_dir: str, filename: str) -> None:
    """Save baseline to JSON file in app/baselines/."""
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, filename)
    
    with open(filepath, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    print(f"✓ Saved {filename}")


def main():
    """Main entry point."""
    metrics_file = "logs/metrics.jsonl"
    baselines_dir = "app/baselines"
    
    print("=" * 60)
    print("Generating Baselines for Anomaly Detection")
    print("=" * 60)
    
    # Load metrics
    metrics = load_metrics(metrics_file)
    if not metrics:
        print("No metrics to process. Run run_metrics.py first.")
        return
    
    print(f"\nGenerating baselines from {len(metrics)} metric windows...\n")
    
    # Generate all baselines
    baselines = {
        "bandwidth": (generate_bandwidth_baseline, "baseline_bandwidth.json"),
        "latency": (generate_latency_baseline, "baseline_latency.json"),
        "protocol": (generate_protocol_baseline, "baseline_protocols.json"),
        "connection": (generate_connection_baseline, "baseline_connections.json"),
    }
    
    for baseline_type, (generator, filename) in baselines.items():
        baseline = generator(metrics)
        save_baseline(baseline, baselines_dir, filename)
    
    print("\n" + "=" * 60)
    print("Baseline generation complete!")
    print(f"Baselines saved to: {baselines_dir}/")
    print("=" * 60)


if __name__ == "__main__":
    main()
