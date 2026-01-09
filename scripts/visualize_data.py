#!/usr/bin/env python3
"""
Network Traffic Analyzer - Data Visualization & Analysis Examples

This module demonstrates how matplotlib and pandas integrate with the API.

Matplotlib & Pandas Role in the System:
- Pandas: Data manipulation, windowing, aggregation (used in baseline generation)
- Matplotlib: Time-series visualization (future integration with API)
"""

import json
import os
import sys
from typing import Dict, List, Any, Tuple
from datetime import datetime

try:
    import matplotlib.pyplot as plt
    import matplotlib.dates as mdates
    import numpy as np
    import pandas as pd
    HAS_VIZ = True
except ImportError:
    HAS_VIZ = False
    print("Warning: matplotlib/pandas not available for visualization")


def load_metrics_jsonl(filepath: str) -> pd.DataFrame:
    """
    Load metrics JSONL file into pandas DataFrame for analysis.
    
    Args:
        filepath: Path to metrics.jsonl
    
    Returns:
        DataFrame with columns: window_start, window_end, bandwidth_bps, 
                               latency_ms, connections, protocol, etc.
    """
    data = []
    
    if not os.path.exists(filepath):
        print(f"Metrics file not found: {filepath}")
        return pd.DataFrame()
    
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    record = json.loads(line)
                    
                    # Extract key metrics
                    flat_record = {
                        'window_start': record.get('window_start'),
                        'window_end': record.get('window_end'),
                        'window_mid': (record.get('window_start', 0) + record.get('window_end', 0)) / 2,
                        'bandwidth_bps': record.get('bandwidth', {}).get('mean_bps', 0),
                        'bandwidth_max_bps': record.get('bandwidth', {}).get('max_bps', 0),
                        'latency_ms': record.get('latency', {}).get('mean_rtt', 0),
                        'latency_p95_ms': record.get('latency', {}).get('p95_rtt', 0),
                        'total_connections': record.get('connections', {}).get('total', 0),
                        'packet_count': record.get('record_count', 0),
                    }
                    
                    # Extract protocol distribution
                    protocol = record.get('protocol', {})
                    flat_record['protocol_tcp_pct'] = protocol.get('tcp', {}).get('percentage', 0)
                    flat_record['protocol_udp_pct'] = protocol.get('udp', {}).get('percentage', 0)
                    flat_record['protocol_icmp_pct'] = protocol.get('icmp', {}).get('percentage', 0)
                    
                    data.append(flat_record)
                
                except json.JSONDecodeError:
                    continue
    
    df = pd.DataFrame(data)
    
    if not df.empty:
        # Convert timestamps to datetime
        df['timestamp'] = pd.to_datetime(df['window_mid'], unit='s')
    
    return df


def load_anomalies_jsonl(filepath: str) -> pd.DataFrame:
    """
    Load anomalies JSONL file into pandas DataFrame.
    
    Args:
        filepath: Path to anomalies.jsonl
    
    Returns:
        DataFrame with columns: type, severity, window_start, message, etc.
    """
    data = []
    
    if not os.path.exists(filepath):
        print(f"Anomalies file not found: {filepath}")
        return pd.DataFrame()
    
    with open(filepath, 'r') as f:
        for line_num, line in enumerate(f):
            if line.strip():
                try:
                    # Handle nested structure (some anomalies are wrapped)
                    record = json.loads(line)
                    
                    # Extract anomalies list if nested
                    anomalies_list = record.get('anomalies', [record])
                    
                    for anom in anomalies_list:
                        flat_record = {
                            'type': anom.get('type'),
                            'severity': anom.get('severity'),
                            'window_start': anom.get('window_start'),
                            'window_end': anom.get('window_end'),
                            'message': anom.get('message'),
                            'metric': anom.get('metric'),
                            'current_value': anom.get('current_value'),
                            'threshold': anom.get('threshold'),
                        }
                        data.append(flat_record)
                
                except json.JSONDecodeError:
                    continue
    
    df = pd.DataFrame(data)
    
    if not df.empty:
        df['timestamp'] = pd.to_datetime(df['window_start'], unit='s')
    
    return df


def analyze_metrics(metrics_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Perform statistical analysis on metrics using pandas.
    
    Args:
        metrics_df: DataFrame from load_metrics_jsonl()
    
    Returns:
        Dictionary with statistical summaries
    """
    if metrics_df.empty:
        return {}
    
    analysis = {
        'total_windows': len(metrics_df),
        'time_span_seconds': (
            metrics_df['window_end'].max() - metrics_df['window_start'].min()
        ) if len(metrics_df) > 0 else 0,
        
        'bandwidth': {
            'mean_bps': float(metrics_df['bandwidth_bps'].mean()),
            'median_bps': float(metrics_df['bandwidth_bps'].median()),
            'std_bps': float(metrics_df['bandwidth_bps'].std()),
            'min_bps': float(metrics_df['bandwidth_bps'].min()),
            'max_bps': float(metrics_df['bandwidth_bps'].max()),
            'p95_bps': float(metrics_df['bandwidth_bps'].quantile(0.95)),
        },
        
        'latency': {
            'mean_ms': float(metrics_df['latency_ms'].mean()),
            'median_ms': float(metrics_df['latency_ms'].median()),
            'std_ms': float(metrics_df['latency_ms'].std()),
            'min_ms': float(metrics_df['latency_ms'].min()),
            'max_ms': float(metrics_df['latency_ms'].max()),
            'p95_ms': float(metrics_df['latency_p95_ms'].quantile(0.95)),
        },
        
        'connections': {
            'mean_per_window': float(metrics_df['total_connections'].mean()),
            'total': int(metrics_df['total_connections'].sum()),
            'max_per_window': int(metrics_df['total_connections'].max()),
        },
        
        'protocols': {
            'tcp_avg_pct': float(metrics_df['protocol_tcp_pct'].mean()),
            'udp_avg_pct': float(metrics_df['protocol_udp_pct'].mean()),
            'icmp_avg_pct': float(metrics_df['protocol_icmp_pct'].mean()),
        }
    }
    
    return analysis


def analyze_anomalies(anomalies_df: pd.DataFrame) -> Dict[str, Any]:
    """
    Analyze anomalies using pandas aggregations.
    
    Args:
        anomalies_df: DataFrame from load_anomalies_jsonl()
    
    Returns:
        Dictionary with anomaly statistics
    """
    if anomalies_df.empty:
        return {'total': 0}
    
    analysis = {
        'total': len(anomalies_df),
        
        'by_type': (
            anomalies_df.groupby('type')
            .size()
            .to_dict()
        ),
        
        'by_severity': (
            anomalies_df.groupby('severity')
            .size()
            .to_dict()
        ),
        
        'cross_type_severity': (
            anomalies_df
            .groupby(['type', 'severity'])
            .size()
            .to_dict()
        ),
    }
    
    return analysis


def plot_bandwidth_timeline(metrics_df: pd.DataFrame, output_file: str = 'bandwidth_timeline.png'):
    """
    Plot bandwidth over time using matplotlib.
    
    Args:
        metrics_df: DataFrame from load_metrics_jsonl()
        output_file: Path to save PNG
    """
    if not HAS_VIZ or metrics_df.empty:
        print("Visualization not available (matplotlib/pandas missing or no data)")
        return
    
    fig, ax = plt.subplots(figsize=(14, 6))
    
    # Plot bandwidth
    ax.plot(metrics_df['timestamp'], metrics_df['bandwidth_bps'], 
            linewidth=2, label='Mean BPS', color='blue', marker='o', markersize=4)
    ax.fill_between(metrics_df['timestamp'], 
                     metrics_df['bandwidth_bps'] - metrics_df['bandwidth_bps'].std(),
                     metrics_df['bandwidth_bps'] + metrics_df['bandwidth_bps'].std(),
                     alpha=0.2, color='blue', label='±1σ')
    
    ax.set_xlabel('Time', fontsize=12)
    ax.set_ylabel('Bandwidth (Bps)', fontsize=12)
    ax.set_title('Network Bandwidth Over Time', fontsize=14, fontweight='bold')
    ax.legend(loc='best')
    ax.grid(True, alpha=0.3)
    
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_file, dpi=100)
    print(f"✓ Saved: {output_file}")
    plt.close()


def plot_latency_timeline(metrics_df: pd.DataFrame, output_file: str = 'latency_timeline.png'):
    """
    Plot latency (RTT) over time using matplotlib.
    
    Args:
        metrics_df: DataFrame from load_metrics_jsonl()
        output_file: Path to save PNG
    """
    if not HAS_VIZ or metrics_df.empty:
        print("Visualization not available (matplotlib/pandas missing or no data)")
        return
    
    fig, ax = plt.subplots(figsize=(14, 6))
    
    # Plot latency with percentile bands
    ax.plot(metrics_df['timestamp'], metrics_df['latency_ms'], 
            linewidth=2, label='Mean RTT', color='green', marker='o', markersize=4)
    ax.plot(metrics_df['timestamp'], metrics_df['latency_p95_ms'],
            linewidth=1.5, label='P95 RTT', color='orange', linestyle='--', alpha=0.7)
    
    ax.set_xlabel('Time', fontsize=12)
    ax.set_ylabel('Latency (ms)', fontsize=12)
    ax.set_title('Request-Response Latency Over Time', fontsize=14, fontweight='bold')
    ax.legend(loc='best')
    ax.grid(True, alpha=0.3)
    
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_file, dpi=100)
    print(f"✓ Saved: {output_file}")
    plt.close()


def plot_protocol_distribution(metrics_df: pd.DataFrame, output_file: str = 'protocols.png'):
    """
    Plot protocol distribution over time using matplotlib.
    
    Args:
        metrics_df: DataFrame from load_metrics_jsonl()
        output_file: Path to save PNG
    """
    if not HAS_VIZ or metrics_df.empty:
        print("Visualization not available (matplotlib/pandas missing or no data)")
        return
    
    fig, ax = plt.subplots(figsize=(14, 6))
    
    ax.plot(metrics_df['timestamp'], metrics_df['protocol_tcp_pct'],
            label='TCP %', marker='o', markersize=4)
    ax.plot(metrics_df['timestamp'], metrics_df['protocol_udp_pct'],
            label='UDP %', marker='s', markersize=4)
    ax.plot(metrics_df['timestamp'], metrics_df['protocol_icmp_pct'],
            label='ICMP %', marker='^', markersize=4)
    
    ax.set_xlabel('Time', fontsize=12)
    ax.set_ylabel('Protocol Distribution (%)', fontsize=12)
    ax.set_title('Protocol Distribution Over Time', fontsize=14, fontweight='bold')
    ax.legend(loc='best')
    ax.grid(True, alpha=0.3)
    ax.set_ylim([0, 100])
    
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_file, dpi=100)
    print(f"✓ Saved: {output_file}")
    plt.close()


def plot_anomaly_heatmap(metrics_df: pd.DataFrame, anomalies_df: pd.DataFrame,
                         output_file: str = 'anomaly_heatmap.png'):
    """
    Plot anomalies overlaid on metrics timeline.
    
    Args:
        metrics_df: DataFrame from load_metrics_jsonl()
        anomalies_df: DataFrame from load_anomalies_jsonl()
        output_file: Path to save PNG
    """
    if not HAS_VIZ or metrics_df.empty:
        print("Visualization not available (matplotlib/pandas missing or no data)")
        return
    
    fig, ax = plt.subplots(figsize=(14, 6))
    
    # Plot bandwidth as baseline
    ax.plot(metrics_df['timestamp'], metrics_df['bandwidth_bps'],
            linewidth=2, label='Bandwidth', color='blue', alpha=0.7)
    
    # Overlay anomalies as vertical lines with colors by severity
    severity_colors = {'medium': 'orange', 'high': 'red'}
    plotted_severities = set()
    
    for severity in anomalies_df['severity'].unique():
        if pd.isna(severity):
            continue
        severity_data = anomalies_df[anomalies_df['severity'] == severity]
        for _, row in severity_data.iterrows():
            if pd.notna(row['window_start']):
                ts = pd.to_datetime(row['window_start'], unit='s')
                ax.axvline(x=ts,
                          color=severity_colors.get(severity, 'gray'),
                          linewidth=1.5, alpha=0.5, linestyle='--')
                plotted_severities.add(severity)
    
    # Create custom legend
    from matplotlib.lines import Line2D
    legend_elements = [
        Line2D([0], [0], color='blue', linewidth=2, label='Bandwidth'),
    ]
    if 'medium' in plotted_severities:
        legend_elements.append(
            Line2D([0], [0], color='orange', linewidth=1.5, linestyle='--', label='Medium Anomaly')
        )
    if 'high' in plotted_severities:
        legend_elements.append(
            Line2D([0], [0], color='red', linewidth=1.5, linestyle='--', label='High Anomaly')
        )
    
    ax.legend(handles=legend_elements, loc='best')
    
    ax.set_xlabel('Time', fontsize=12)
    ax.set_ylabel('Bandwidth (Bps)', fontsize=12)
    ax.set_title('Anomalies Overlaid on Metrics Timeline', fontsize=14, fontweight='bold')
    ax.grid(True, alpha=0.3)
    
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(output_file, dpi=100)
    print(f"✓ Saved: {output_file}")
    plt.close()


def main():
    """Generate all visualizations."""
    print("\n" + "="*70)
    print("Network Traffic Analyzer - Data Analysis & Visualization")
    print("="*70 + "\n")
    
    # Load data
    print("Loading data...")
    metrics_df = load_metrics_jsonl('logs/metrics.jsonl')
    anomalies_df = load_anomalies_jsonl('logs/anomalies.jsonl')
    
    if metrics_df.empty:
        print("No metrics data found. Run API first: POST /api/metrics/compute")
        return
    
    print(f"✓ Loaded {len(metrics_df)} metric windows")
    print(f"✓ Loaded {len(anomalies_df)} anomalies\n")
    
    # Analyze
    print("Performing analysis...")
    metrics_analysis = analyze_metrics(metrics_df)
    anomalies_analysis = analyze_anomalies(anomalies_df)
    
    print("\nMETRICS ANALYSIS")
    print("-" * 70)
    print(f"Time Span: {metrics_analysis.get('time_span_seconds', 0):.0f} seconds")
    print(f"Windows: {metrics_analysis.get('total_windows', 0)}")
    print(f"Bandwidth: {metrics_analysis.get('bandwidth', {}).get('mean_bps', 0):.0f} Bps mean")
    print(f"Latency: {metrics_analysis.get('latency', {}).get('mean_ms', 0):.2f} ms mean")
    print(f"Connections: {metrics_analysis.get('connections', {}).get('total', 0)} total")
    
    print("\nANOMALIES ANALYSIS")
    print("-" * 70)
    print(f"Total: {anomalies_analysis.get('total', 0)}")
    for atype, count in anomalies_analysis.get('by_type', {}).items():
        print(f"  {atype}: {count}")
    
    # Generate visualizations
    print("\nGENERATING VISUALIZATIONS")
    print("-" * 70)
    
    if HAS_VIZ:
        plot_bandwidth_timeline(metrics_df, 'reports/bandwidth_timeline.png')
        plot_latency_timeline(metrics_df, 'reports/latency_timeline.png')
        plot_protocol_distribution(metrics_df, 'reports/protocol_distribution.png')
        plot_anomaly_heatmap(metrics_df, anomalies_df, 'reports/anomaly_heatmap.png')
    else:
        print("⚠ matplotlib/pandas not available - skipping visualizations")
    
    print("\nAnalysis complete!")


if __name__ == '__main__':
    main()
