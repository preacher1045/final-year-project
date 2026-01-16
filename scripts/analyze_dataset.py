#!/usr/bin/env python3
"""
Dataset Analysis Utility

Analyzes PCAP files and metrics to recommend optimal training strategies.
Useful for large datasets where you want to understand sampling needs before training.

Usage:
    python scripts/analyze_dataset.py --metrics logs/metrics.jsonl
    python scripts/analyze_dataset.py --pcap data/raw/pcapng/test.pcapng
"""

import json
import os
import sys
import argparse
import subprocess
from pathlib import Path
import numpy as np
from typing import Dict, List, Any

def load_metrics(filepath: str) -> List[Dict[str, Any]]:
    """Load metrics from JSONL file."""
    metrics = []
    try:
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        metrics.append(json.loads(line))
                    except:
                        pass
    except Exception as e:
        print(f"❌ Error loading metrics: {e}", file=sys.stderr)
    return metrics

def analyze_metrics(metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze metrics characteristics."""
    if not metrics:
        return {'error': 'No metrics found'}
    
    # Extract bandwidth values
    bps_values = []
    pps_values = []
    latency_values = []
    
    for m in metrics:
        bps = m.get('bandwidth', {}).get('avg_bps', 0)
        if bps > 0:
            bps_values.append(bps)
        
        pps = m.get('bandwidth', {}).get('avg_pps', 0)
        if pps > 0:
            pps_values.append(pps)
        
        latency = m.get('latency', {}).get('request_response', {}).get('mean', 0)
        if latency > 0:
            latency_values.append(latency)
    
    # Calculate statistics
    stats = {
        'total_windows': len(metrics),
        'bandwidth_mbps': {
            'mean': round(np.mean(bps_values) / 1e6, 2) if bps_values else 0,
            'std': round(np.std(bps_values) / 1e6, 2) if bps_values else 0,
            'min': round(np.min(bps_values) / 1e6, 2) if bps_values else 0,
            'max': round(np.max(bps_values) / 1e6, 2) if bps_values else 0,
        },
        'packets_per_sec': {
            'mean': round(np.mean(pps_values), 0) if pps_values else 0,
            'std': round(np.std(pps_values), 0) if pps_values else 0,
            'min': round(np.min(pps_values), 0) if pps_values else 0,
            'max': round(np.max(pps_values), 0) if pps_values else 0,
        },
        'latency_ms': {
            'mean': round(np.mean(latency_values), 2) if latency_values else 0,
            'std': round(np.std(latency_values), 2) if latency_values else 0,
            'min': round(np.min(latency_values), 2) if latency_values else 0,
            'max': round(np.max(latency_values), 2) if latency_values else 0,
        }
    }
    
    # Calculate coefficient of variation for bandwidth
    if bps_values:
        mean_bps = np.mean(bps_values)
        std_bps = np.std(bps_values)
        cv = std_bps / mean_bps if mean_bps > 0 else 0
        stats['coefficient_of_variation'] = round(cv, 3)
        stats['variance_type'] = 'high' if cv > 0.5 else 'moderate' if cv > 0.2 else 'low'
    
    # Calculate time span
    if len(metrics) > 1:
        first_ts = metrics[0].get('timestamp', 0)
        last_ts = metrics[-1].get('timestamp', 0)
        if last_ts > first_ts:
            duration = last_ts - first_ts
            stats['duration_seconds'] = int(duration)
            stats['window_interval_seconds'] = round(duration / (len(metrics) - 1), 1)
    
    return stats

def get_recommendations(total_windows: int, cv: float) -> Dict[str, Any]:
    """Get sampling recommendations based on dataset size and variance."""
    recommendations = {
        'total_samples': total_windows,
        'samples_for_training': None,
        'sampling_strategy': 'uniform',
        'sample_rate': 1.0,
        'reasoning': ''
    }
    
    # Isolation Forest optimal: 500-5000 samples
    if total_windows <= 100:
        recommendations['samples_for_training'] = total_windows
        recommendations['sample_rate'] = 1.0
        recommendations['sampling_strategy'] = 'use_all'
        recommendations['reasoning'] = '✓ Dataset is small; use all samples'
    
    elif total_windows <= 500:
        recommendations['samples_for_training'] = total_windows
        recommendations['sample_rate'] = 1.0
        recommendations['sampling_strategy'] = 'use_all'
        recommendations['reasoning'] = '✓ Dataset size is optimal for Isolation Forest'
    
    elif total_windows <= 5000:
        if cv > 0.5:
            recommendations['sample_rate'] = 1.0
            recommendations['samples_for_training'] = total_windows
            recommendations['sampling_strategy'] = 'use_all'
            recommendations['reasoning'] = '✓ High variance detected; use all data for better coverage'
        else:
            recommendations['sample_rate'] = 0.8
            recommendations['samples_for_training'] = int(total_windows * 0.8)
            recommendations['sampling_strategy'] = 'stratified'
            recommendations['reasoning'] = '≈ Uniform data; use 80% via stratified sampling'
    
    elif total_windows <= 10000:
        if cv > 0.5:
            recommendations['sample_rate'] = 0.6
            recommendations['samples_for_training'] = int(total_windows * 0.6)
            recommendations['sampling_strategy'] = 'stratified'
            recommendations['reasoning'] = '~ High variance; use 60% stratified to get ~6000 samples'
        else:
            recommendations['sample_rate'] = 0.4
            recommendations['samples_for_training'] = int(total_windows * 0.4)
            recommendations['sampling_strategy'] = 'systematic'
            recommendations['reasoning'] = '~ Uniform data; use 40% systematic to get ~4000 samples'
    
    else:  # > 10000
        if cv > 0.5:
            recommendations['sample_rate'] = 0.3
            recommendations['samples_for_training'] = max(500, int(total_windows * 0.3))
            recommendations['sampling_strategy'] = 'stratified'
            recommendations['reasoning'] = '⚠ Large dataset with high variance; use 30% stratified'
        else:
            recommendations['sample_rate'] = 0.15
            recommendations['samples_for_training'] = max(500, int(total_windows * 0.15))
            recommendations['sampling_strategy'] = 'systematic'
            recommendations['reasoning'] = '⚠ Large uniform dataset; use 15% systematic'
    
    return recommendations

def print_report(metrics_path: str = None, pcap_path: str = None):
    """Print analysis report."""
    metrics = []
    
    if metrics_path and os.path.exists(metrics_path):
        print(f"📊 Loading metrics from: {metrics_path}")
        metrics = load_metrics(metrics_path)
        print(f"✓ Loaded {len(metrics)} metric windows\n")
    
    elif pcap_path and os.path.exists(pcap_path):
        print(f"📦 Analyzing PCAP: {pcap_path}")
        pcap_size_mb = os.path.getsize(pcap_path) / (1024**2)
        print(f"   File size: {pcap_size_mb:.1f} MB\n")
        
        # Compute metrics
        print("⏳ Computing metrics... (this may take a while for large files)")
        metrics_file = '/tmp/temp_metrics.jsonl'
        cmd = [
            sys.executable,
            'scripts/extract_metrics_sampled.py',
            '--pcap', pcap_path,
            '--sample-rate', '0.10',
            '--out', metrics_file
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                metrics = load_metrics(metrics_file)
                print(f"✓ Computed metrics for {len(metrics)} windows\n")
            else:
                print(f"❌ Metrics computation failed: {result.stderr}", file=sys.stderr)
                return
        except subprocess.TimeoutExpired:
            print("❌ Metrics computation timed out (>10 minutes)", file=sys.stderr)
            return
        except Exception as e:
            print(f"❌ Error: {e}", file=sys.stderr)
            return
    
    if not metrics:
        print("❌ No metrics to analyze", file=sys.stderr)
        return
    
    # Analyze
    stats = analyze_metrics(metrics)
    
    if 'error' in stats:
        print(f"❌ {stats['error']}", file=sys.stderr)
        return
    
    # Get recommendations
    cv = stats.get('coefficient_of_variation', 0)
    recs = get_recommendations(stats['total_windows'], cv)
    
    # Print report
    print("=" * 70)
    print("DATASET ANALYSIS REPORT")
    print("=" * 70)
    
    print("\n📈 METRIC WINDOWS:")
    print(f"  Total windows: {stats['total_windows']}")
    if 'duration_seconds' in stats:
        print(f"  Duration: {stats['duration_seconds']} seconds")
        print(f"  Window interval: {stats['window_interval_seconds']} seconds")
    
    print("\n📊 BANDWIDTH CHARACTERISTICS:")
    bw = stats['bandwidth_mbps']
    print(f"  Mean: {bw['mean']} Mbps")
    print(f"  Std Dev: {bw['std']} Mbps")
    print(f"  Range: {bw['min']}-{bw['max']} Mbps")
    print(f"  Variance Type: {stats.get('variance_type', 'unknown')}")
    if 'coefficient_of_variation' in stats:
        print(f"  Coefficient of Variation: {stats['coefficient_of_variation']}")
    
    print("\n📥 PACKETS/SEC:")
    pps = stats['packets_per_sec']
    print(f"  Mean: {pps['mean']:.0f} pps")
    print(f"  Std Dev: {pps['std']:.0f} pps")
    print(f"  Range: {pps['min']:.0f}-{pps['max']:.0f} pps")
    
    print("\n⏱️  LATENCY CHARACTERISTICS:")
    lat = stats['latency_ms']
    print(f"  Mean: {lat['mean']} ms")
    print(f"  Std Dev: {lat['std']} ms")
    print(f"  Range: {lat['min']}-{lat['max']} ms")
    
    print("\n" + "=" * 70)
    print("TRAINING RECOMMENDATIONS")
    print("=" * 70)
    print(f"  {recs['reasoning']}")
    print(f"\n  Sampling Strategy: {recs['sampling_strategy'].upper()}")
    print(f"  Sample Rate: {recs['sample_rate']*100:.1f}%")
    print(f"  Training Samples: {recs['samples_for_training']}")
    print(f"  Memory Savings: ~{(1-recs['sample_rate'])*100:.0f}%")
    print("\n" + "=" * 70)
    
    print("\n📝 USAGE:")
    if recs['sample_rate'] == 1.0:
        print(f"""
  Training with ALL data:
  $ curl -X POST http://localhost:5000/api/train \\
    -H "Content-Type: application/json" \\
    -d '{{"file_id": "<your_file_id>"}}' 
""")
    else:
        strategy = recs['sampling_strategy'].split('_')[0].lower()
        if len(recs['sampling_strategy'].split('_')) > 1:
            rate = float(recs['sampling_strategy'].split('_')[1])
        else:
            rate = recs['sample_rate']
        
        print(f"""
  Training with {recs['sample_rate']*100:.0f}% sampling ({strategy}):
  $ curl -X POST http://localhost:5000/api/train \\
    -H "Content-Type: application/json" \\
    -d '{{
      "file_id": "<your_file_id>",
      "sample_rate": {recs['sample_rate']},
      "sampling_strategy": "{strategy}"
    }}'
""")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Analyze dataset characteristics for training recommendations'
    )
    parser.add_argument('--metrics', help='Path to metrics JSONL file')
    parser.add_argument('--pcap', help='Path to PCAP file (will compute metrics)')
    
    args = parser.parse_args()
    
    if not args.metrics and not args.pcap:
        parser.print_help()
        sys.exit(1)
    
    print_report(metrics_path=args.metrics, pcap_path=args.pcap)
