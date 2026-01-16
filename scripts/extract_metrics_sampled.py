#!/usr/bin/env python3
"""
Efficient Metrics Extraction with Sampling

For large PCAP files (100M+ packets), this extracts metrics more efficiently
by sampling packets during extraction rather than processing every single packet.

Usage:
    python scripts/extract_metrics_sampled.py --pcap data/training_data/202601011400.pcap \\
        --window 10 --sample-rate 0.01 --out logs/training_metrics.jsonl

For a 9.7GB file with 150M packets:
    - sample-rate=0.01 → ~1.5M packets (~1% sampling) → ~2-5 minutes
    - sample-rate=0.05 → ~7.5M packets (~5% sampling) → ~5-10 minutes
    - sample-rate=0.10 → ~15M packets (~10% sampling) → ~10-20 minutes
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Dict, Any, List, Optional
import random

try:
    import pyshark
except ImportError:
    print("Error: pyshark not installed. Install with: pip install pyshark")
    sys.exit(1)

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analysis.traffic_metric import compute_metrics, normalize_record, deduplicate_records
from app.analysis.bandwidth_analysis import compute_bandwidth_metrics
from app.analysis.latency_analysis import compute_latency_metrics
from app.analysis.connection_analysis import compute_connection_metrics
from app.analysis.protocol_distribution import compute_protocol_distribution
from app.analysis.flow_enrichment import FlowEnricher


def extract_packet_data(packet) -> Optional[Dict[str, Any]]:
    """Extract relevant fields from a pyshark packet."""
    try:
        # Get timestamp
        if hasattr(packet, 'frame_info'):
            timestamp = float(packet.frame_info.time_epoch)
        else:
            timestamp = None
        
        if timestamp is None:
            return None
        
        # Get basic info
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        protocol = None
        length = 0
        
        if 'IP' in packet:
            ip_layer = packet['IP']
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            length = int(ip_layer.len) if hasattr(ip_layer, 'len') else 0
        elif 'IPv6' in packet:
            ip_layer = packet['IPv6']
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            length = int(ip_layer.plen) if hasattr(ip_layer, 'plen') else 0
        
        if 'TCP' in packet:
            tcp = packet['TCP']
            protocol = 'TCP'
            src_port = int(tcp.srcport) if hasattr(tcp, 'srcport') else None
            dst_port = int(tcp.dstport) if hasattr(tcp, 'dstport') else None
        elif 'UDP' in packet:
            udp = packet['UDP']
            protocol = 'UDP'
            src_port = int(udp.srcport) if hasattr(udp, 'srcport') else None
            dst_port = int(udp.dstport) if hasattr(udp, 'dstport') else None
        
        if not protocol:
            return None
        
        return {
            'timestamp': timestamp,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'protocol': protocol,
            'length': length,
        }
    
    except Exception:
        return None


def extract_metrics_sampled(
    pcap_path: str,
    window_seconds: int = 10,
    sample_rate: float = 0.01,
    output_file: str = None
) -> List[Dict[str, Any]]:
    """
    Extract metrics from PCAP with sampling.
    
    Args:
        pcap_path: Path to PCAP file
        window_seconds: Window size in seconds
        sample_rate: Fraction of packets to sample (0.0 to 1.0)
        output_file: Optional output file to write JSONL metrics
    
    Returns:
        List of metric windows
    """
    
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found: {pcap_path}")
        sys.exit(1)
    
    if not 0 < sample_rate <= 1.0:
        print(f"Error: sample_rate must be between 0 and 1, got {sample_rate}")
        sys.exit(1)
    
    file_size_mb = os.path.getsize(pcap_path) / (1024**2)
    print(f"\n📦 PCAP File: {pcap_path}")
    print(f"   Size: {file_size_mb:.1f} MB")
    print(f"   Window: {window_seconds}s")
    print(f"   Sample Rate: {sample_rate*100:.1f}%")
    print(f"\n⏳ Extracting packets and computing metrics...")
    
    # Collect sampled records
    records = []
    windows = {}  # timestamp_bucket -> [records]
    packet_count = 0
    sampled_count = 0
    
    try:
        cap = pyshark.FileCapture(
            pcap_path,
            use_json=False,
            keep_packets=False
        )
        
        start_time = None
        
        for packet in cap:
            packet_count += 1
            
            # Sample packets
            if random.random() > sample_rate:
                continue
            
            sampled_count += 1
            
            # Extract data
            data = extract_packet_data(packet)
            if not data:
                continue
            
            ts = data['timestamp']
            if start_time is None:
                start_time = ts
            
            # Bucket into windows
            bucket = int((ts - start_time) // window_seconds)
            if bucket not in windows:
                windows[bucket] = []
            windows[bucket].append(data)
            
            # Progress
            if sampled_count % 100000 == 0:
                print(f"   Processed {packet_count:,} packets, sampled {sampled_count:,}")
        
        cap.close()
        
    except Exception as e:
        print(f"Error reading PCAP: {e}")
        sys.exit(1)
    
    print(f"\n✓ Total packets: {packet_count:,}")
    print(f"✓ Sampled packets: {sampled_count:,}")
    print(f"✓ Metric windows: {len(windows)}")
    
    # Compute metrics for each window
    print(f"\n📊 Computing metrics for {len(windows)} windows...")
    metrics_list = []
    
    for bucket in sorted(windows.keys()):
        window_records = windows[bucket]
        if not window_records:
            continue
        
        try:
            # Normalize and deduplicate
            norm = [normalize_record(r) for r in window_records]
            norm = deduplicate_records(norm)
            
            # Compute metrics
            metrics = compute_metrics(norm)
            metrics['bandwidth'] = compute_bandwidth_metrics(norm)
            metrics['latency'] = compute_latency_metrics(norm)
            metrics['connections'] = compute_connection_metrics(norm)
            metrics['protocol'] = compute_protocol_distribution(norm)
            metrics['window_id'] = bucket
            metrics['window_start'] = start_time + (bucket * window_seconds)
            metrics['window_end'] = start_time + ((bucket + 1) * window_seconds)
            
            metrics_list.append(metrics)
        
        except Exception as e:
            print(f"  ⚠ Error computing metrics for window {bucket}: {e}")
            continue
    
    # Write to file
    if output_file:
        os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
        print(f"\n💾 Writing metrics to: {output_file}")
        
        with open(output_file, 'w') as f:
            for metrics in metrics_list:
                f.write(json.dumps(metrics) + '\n')
        
        print(f"✓ Wrote {len(metrics_list)} metric windows")
    
    print(f"\n✅ Complete!")
    print(f"   Estimated training samples: {len(metrics_list)}")
    print(f"   Sampling compression: {sample_rate*100:.1f}%")
    
    return metrics_list


def main():
    p = argparse.ArgumentParser(
        description="Extract metrics from large PCAP files with sampling"
    )
    p.add_argument('--pcap', default='data/training_data/202601011400.pcap',
                   help='PCAP file path')
    p.add_argument('--window', type=int, default=10,
                   help='Window size in seconds (default: 10)')
    p.add_argument('--sample-rate', type=float, default=0.01,
                   help='Packet sampling rate 0-1 (default: 0.01 = 1%%)')
    p.add_argument('--out', default='logs/training_metrics.jsonl',
                   help='Output metrics file')
    
    args = p.parse_args()
    
    extract_metrics_sampled(
        args.pcap,
        window_seconds=args.window,
        sample_rate=args.sample_rate,
        output_file=args.out
    )


if __name__ == '__main__':
    main()
