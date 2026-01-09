"""Runner to compute metrics from parser outputs in windows.

Usage: run from project root:
  PYTHONPATH=. python scripts/run_metrics.py --window 10 --out logs/metrics.jsonl

This script calls existing parsers to obtain parsed records, windows them by timestamp,
and computes metrics for each window using `compute_metrics`. Also includes flow-level
enrichment (port scans, packet loss indicators) when available.
"""
import argparse
import json
import os
from datetime import datetime
from app.parser import ether_parser, ip_parser, tcp_parser, udp_parser
from app.analysis.traffic_metric import compute_metrics, normalize_record, deduplicate_records
from app.analysis.bandwidth_analysis import compute_bandwidth_metrics
from app.analysis.latency_analysis import compute_latency_metrics
from app.analysis.connection_analysis import compute_connection_metrics
from app.analysis.protocol_distribution import compute_protocol_distribution
from app.analysis.flow_enrichment import FlowEnricher


def parse_iso(ts):
    if ts is None:
        return None
    try:
        # try numeric first
        return float(ts)
    except Exception:
        try:
            dt = datetime.fromisoformat(ts)
            return dt.timestamp()
        except Exception:
            return None


def collect_all_records(pcap_path):
    # Call parsers — they accept full path
    recs = []
    recs += ether_parser.parse_ethernet_frames(pcap_path)
    recs += ip_parser.parse_ip_packets(pcap_path)
    recs += tcp_parser.parse_tcp_packets(pcap_path)
    recs += udp_parser.parse_udp_packets(pcap_path)
    return recs


def window_and_compute(records, window_seconds, out_path=None, flow_data=None):
    # normalize records and deduplicate to avoid double-counting
    norm = [normalize_record(r) for r in records]
    norm = deduplicate_records(norm)
    # normalize timestamps to float and attach _ts
    tmp = []
    for r2 in norm:
        ts = parse_iso(r2.get('timestamp'))
        if ts is None:
            continue
        r2['_ts'] = ts
        tmp.append(r2)
    norm = tmp

    if not norm:
        print('No records with timestamps')
        return

    norm.sort(key=lambda x: x['_ts'])
    start = norm[0]['_ts']
    end = norm[-1]['_ts']

    window_start = start
    outputs = []
    while window_start <= end:
        window_end = window_start + window_seconds
        bucket = [r for r in norm if window_start <= r['_ts'] < window_end]
        # compute metrics using deduplicated bucket
        metrics = compute_metrics(bucket)
        metrics['bandwidth'] = compute_bandwidth_metrics(bucket)
        metrics['latency'] = compute_latency_metrics(bucket)
        metrics['connections'] = compute_connection_metrics(bucket)
        metrics['protocol'] = compute_protocol_distribution(bucket)
        
        # Add flow-level enrichment data
        if flow_data:
            # Add port scan activity
            metrics['scan_activity'] = flow_data.get('scan_activity', [])
            # Add retransmission stats
            metrics['retransmission_stats'] = flow_data.get('retransmission_stats', [])
        
        metrics['window_start'] = window_start
        metrics['window_end'] = window_end
        metrics['record_count'] = len(bucket)
        outputs.append(metrics)
        if out_path:
            with open(out_path, 'a') as fh:
                fh.write(json.dumps(metrics) + '\n')
        window_start = window_end

    return outputs


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--pcap', default=os.path.join('data', 'raw', 'pcapng', 'test_net_traffic.pcapng'))
    p.add_argument('--window', type=int, default=10)
    p.add_argument('--out', default='logs/metrics.jsonl')
    args = p.parse_args()

    pcap_path = os.path.abspath(args.pcap)
    print('Using PCAP:', pcap_path)
    
    # Collect records from parsers
    records = collect_all_records(pcap_path)
    print('Collected', len(records), 'records from parsers')
    
    # Extract flow-level enrichment data
    print('Extracting flow-level data...')
    enricher = FlowEnricher(pcap_path)
    flow_data = {
        'scan_activity': enricher.extract_source_port_scan_activity(),
        'retransmission_stats': enricher.extract_retransmission_stats(),
    }
    print(f'  Found {len(flow_data["scan_activity"])} unique sources')
    print(f'  Found {len(flow_data["retransmission_stats"])} flows with retransmissions')
    
    # Compute metrics with flow enrichment
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    # clear out file
    open(args.out, 'w').close()
    outputs = window_and_compute(records, args.window, out_path=args.out, flow_data=flow_data)
    print('Wrote', len(outputs), 'metric windows to', args.out)


if __name__ == '__main__':
    main()
