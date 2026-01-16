#!/usr/bin/env python3
"""
Fast Metrics Extraction using tshark

Uses tshark (Wireshark CLI) to rapidly extract packets from large PCAP files.
Much faster than pyshark for large datasets.

Usage:
    python scripts/extract_metrics_fast.py --pcap data/training_data/202601011400.pcap \\
        --window 10 --out logs/training_metrics.jsonl
"""

import argparse
import json
import os
import sys
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional
import time

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.analysis.traffic_metric import compute_metrics, normalize_record, deduplicate_records
from app.analysis.bandwidth_analysis import compute_bandwidth_metrics
from app.analysis.latency_analysis import compute_latency_metrics
from app.analysis.connection_analysis import compute_connection_metrics
from app.analysis.protocol_distribution import compute_protocol_distribution


def extract_metrics_with_tshark(
    pcap_path: str,
    window_seconds: int = 10,
    output_file: str = None
) -> List[Dict[str, Any]]:
    """
    Extract metrics from PCAP using tshark for speed.
    
    Args:
        pcap_path: Path to PCAP file
        window_seconds: Window size in seconds
        output_file: Optional output file to write JSONL metrics
    
    Returns:
        List of metric windows
    """
    
    if not os.path.exists(pcap_path):
        print(f"Error: PCAP file not found: {pcap_path}")
        sys.exit(1)
    
    # Check if tshark is available
    try:
        result = subprocess.run(['which', 'tshark'], capture_output=True, text=True)
        if result.returncode != 0:
            print("Error: tshark not found. Install with: sudo apt-get install wireshark")
            sys.exit(1)
    except Exception as e:
        print(f"Error checking tshark: {e}")
        sys.exit(1)
    
    file_size_mb = os.path.getsize(pcap_path) / (1024**2)
    print(f"\n📦 PCAP File: {pcap_path}")
    print(f"   Size: {file_size_mb:.1f} MB")
    print(f"   Window: {window_seconds}s")
    
    print(f"\n⏳ Extracting packet headers with tshark...")
    start_time = time.time()
    
    # Use tshark to extract packet info
    tshark_fields = [
        'frame.time_epoch',
        'ip.src',
        'ip.dst',
        'ipv6.src',
        'ipv6.dst',
        'tcp.srcport',
        'tcp.dstport',
        'udp.srcport',
        'udp.dstport',
        'frame.len',
        'ip.proto',
    ]
    
    # Build tshark command
    cmd = ['tshark', '-r', pcap_path, '-T', 'fields', '-E', 'separator=,']
    for field in tshark_fields:
        cmd.extend(['-e', field])
    
    print(f"   Running: tshark -r {os.path.basename(pcap_path)} (this may take a few minutes)...")
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        windows = {}  # bucket -> records
        packet_count = 0
        first_ts = None
        
        for line in proc.stdout:
            packet_count += 1
            
            if packet_count % 1000000 == 0:
                elapsed = time.time() - start_time
                rate = packet_count / elapsed
                print(f"   Processed {packet_count:,} packets ({rate:.0f} pps)...")
            
            try:
                parts = line.strip().split(',')
                if len(parts) < 2 or not parts[0]:
                    continue
                
                ts = float(parts[0])
                if first_ts is None:
                    first_ts = ts
                
                src_ip = parts[1] or parts[5] or None
                dst_ip = parts[2] or parts[6] or None
                tcp_src = parts[3]
                tcp_dst = parts[4]
                udp_src = parts[7]
                udp_dst = parts[8]
                length = int(parts[9]) if parts[9] else 0
                proto_num = parts[10]
                
                # Determine protocol
                protocol = None
                src_port = None
                dst_port = None
                
                if tcp_src and tcp_dst:
                    protocol = 'TCP'
                    src_port = int(tcp_src)
                    dst_port = int(tcp_dst)
                elif udp_src and udp_dst:
                    protocol = 'UDP'
                    src_port = int(udp_src)
                    dst_port = int(udp_dst)
                else:
                    continue
                
                if not src_ip or not dst_ip:
                    continue
                
                # Bucket into windows
                bucket = int((ts - first_ts) // window_seconds)
                if bucket not in windows:
                    windows[bucket] = []
                
                windows[bucket].append({
                    'timestamp': ts,
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'protocol': protocol,
                    'length': length,
                })
            
            except (ValueError, IndexError):
                continue
        
        proc.wait()
        
        if proc.returncode != 0:
            stderr = proc.stderr.read() if proc.stderr else "Unknown error"
            print(f"Error: tshark failed: {stderr}")
            sys.exit(1)
        
        extraction_time = time.time() - start_time
        print(f"\n✓ Extracted {packet_count:,} packets in {extraction_time:.1f}s")
        print(f"✓ Created {len(windows)} windows")
        
        # Compute metrics
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
                metrics['window_start'] = first_ts + (bucket * window_seconds)
                metrics['window_end'] = first_ts + ((bucket + 1) * window_seconds)
                
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
        
        total_time = time.time() - start_time
        print(f"\n✅ Complete in {total_time:.1f}s")
        print(f"   Training samples ready: {len(metrics_list)} windows")
        
        return metrics_list
    
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


def main():
    p = argparse.ArgumentParser(
        description="Fast metrics extraction from PCAP using tshark"
    )
    p.add_argument('--pcap', default='data/training_data/202601011400.pcap',
                   help='PCAP file path')
    p.add_argument('--window', type=int, default=10,
                   help='Window size in seconds (default: 10)')
    p.add_argument('--out', default='logs/training_metrics.jsonl',
                   help='Output metrics file')
    
    args = p.parse_args()
    
    extract_metrics_with_tshark(
        args.pcap,
        window_seconds=args.window,
        output_file=args.out
    )


if __name__ == '__main__':
    main()
