#!/usr/bin/env python3
"""
Core Anomaly Detection Engine

Orchestrates multiple anomaly detectors and aggregates results.
Provides a unified interface for real-time or batch anomaly detection.

Detectors:
- Traffic Spike Detection (bandwidth-based)
- Excessive Connection Attempts (port scanning)
- High Latency Detection (RTT-based)
- Packet Loss Detection (reliability)
- Abnormal Protocol Usage (deviation from baseline)
- Long-Lived Connections (suspicious duration)

"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime

from app.anomalies.traffic_spike_detector import TrafficSpikeDetector
from app.anomalies.scan_detector import ScanDetector
from app.anomalies.latency_anomaly_detection import LatencyAnomalyDetector
from app.anomalies.packet_loss_detection import PacketLossDetector
from app.anomalies.protocol_anomaly_detection import ProtocolAnomalyDetector
from app.anomalies.long_lived_connections import LongLivedConnectionDetector


class AnomalyEngine:
    """
    Main anomaly detection engine that coordinates multiple detectors.
    
    Severity levels: 'medium', 'high'
    Anomaly types: 'traffic_spike', 'port_scan', 'high_latency', 
                   'packet_loss', 'protocol_anomaly', 'long_lived_conn'
    """
    
    def __init__(self, baselines_dir: str = "app/baselines"):
        """Initialize all anomaly detectors with loaded baselines."""
        self.baselines_dir = baselines_dir
        self.baselines = self._load_baselines()
        
        # Initialize detectors
        self.detectors = {
            'traffic_spike': TrafficSpikeDetector(
                self.baselines.get('bandwidth', {})
            ),
            'port_scan': ScanDetector(),
            'high_latency': LatencyAnomalyDetector(
                self.baselines.get('latency', {})
            ),
            'packet_loss': PacketLossDetector(),
            'protocol_anomaly': ProtocolAnomalyDetector(
                self.baselines.get('protocol', {})
            ),
            'long_lived_conn': LongLivedConnectionDetector(
                self.baselines.get('connection', {})
            ),
        }
        
        self.detections = []  # History of all detections
    
    def _load_baselines(self) -> Dict[str, Any]:
        """Load baseline profiles from JSON files."""
        baselines = {}
        baseline_files = {
            'bandwidth': 'baseline_bandwidth.json',
            'latency': 'baseline_latency.json',
            'protocol': 'baseline_protocols.json',
            'connection': 'baseline_connections.json',
        }
        
        for key, filename in baseline_files.items():
            filepath = os.path.join(self.baselines_dir, filename)
            if os.path.exists(filepath):
                try:
                    with open(filepath, 'r') as f:
                        baselines[key] = json.load(f)
                except Exception as e:
                    print(f"Warning: Failed to load {filename}: {e}")
            else:
                print(f"Warning: Baseline file not found: {filename}")
        
        return baselines
    
    def analyze_metric_window(
        self, 
        metric_window: Dict[str, Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a single metric window for anomalies.
        
        Args:
            metric_window: Output from scripts/run_metrics.py (one window from JSONL)
            context: Optional context dict (e.g., historical data for rolling calcs)
        
        Returns:
            Dict with anomalies list and summary
        """
        anomalies = []
        window_start = metric_window.get('window_start')
        window_end = metric_window.get('window_end')
        
        # Run each detector
        spike_results = self.detectors['traffic_spike'].detect(metric_window)
        if spike_results:
            anomalies.extend(spike_results)
        
        latency_results = self.detectors['high_latency'].detect(metric_window)
        if latency_results:
            anomalies.extend(latency_results)
        
        loss_results = self.detectors['packet_loss'].detect(metric_window)
        if loss_results:
            anomalies.extend(loss_results)
        
        proto_results = self.detectors['protocol_anomaly'].detect(metric_window)
        if proto_results:
            anomalies.extend(proto_results)
        
        conn_results = self.detectors['long_lived_conn'].detect(metric_window)
        if conn_results:
            anomalies.extend(conn_results)
        
        # Port scan detector needs flow-level data (future enhancement)
        # For now, it requires external data sources
        
        # Build summary
        result = {
            'window_start': window_start,
            'window_end': window_end,
            'timestamp': datetime.utcnow().isoformat(),
            'anomaly_count': len(anomalies),
            'anomalies': anomalies,
            'summary': self._summarize_anomalies(anomalies)
        }
        
        # Store in history
        self.detections.append(result)
        
        return result
    
    def _summarize_anomalies(self, anomalies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize anomalies by type and severity."""
        summary = {
            'by_type': {},
            'by_severity': {'medium': 0, 'high': 0}
        }
        
        for anom in anomalies:
            anom_type = anom.get('type', 'unknown')
            severity = anom.get('severity', 'medium')
            
            if anom_type not in summary['by_type']:
                summary['by_type'][anom_type] = {'medium': 0, 'high': 0}
            
            summary['by_type'][anom_type][severity] += 1
            summary['by_severity'][severity] += 1
        
        return summary
    
    def batch_analyze(
        self, 
        metrics_jsonl: str = "logs/metrics.jsonl"
    ) -> List[Dict[str, Any]]:
        """
        Batch analyze all metric windows from JSONL file.
        
        Args:
            metrics_jsonl: Path to JSONL file with metric windows
        
        Returns:
            List of analysis results (one per window)
        """
        results = []
        
        if not os.path.exists(metrics_jsonl):
            print(f"Error: Metrics file not found: {metrics_jsonl}")
            return results
        
        print(f"Analyzing {metrics_jsonl}...")
        
        with open(metrics_jsonl, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                
                try:
                    metric_window = json.loads(line)
                    result = self.analyze_metric_window(metric_window)
                    results.append(result)
                    
                    if result['anomaly_count'] > 0:
                        print(f"  Window {line_num}: {result['anomaly_count']} anomalies detected")
                
                except json.JSONDecodeError as e:
                    print(f"  Window {line_num}: JSON decode error: {e}")
        
        print(f"Analysis complete: {len(results)} windows processed")
        return results
    
    def export_detections(self, output_file: str = "logs/anomalies.jsonl") -> None:
        """Export all detections to JSONL file."""
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        
        with open(output_file, 'w') as f:
            for detection in self.detections:
                f.write(json.dumps(detection) + '\n')
        
        print(f"✓ Exported {len(self.detections)} detection results to {output_file}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get overall anomaly statistics."""
        if not self.detections:
            return {'total_windows': 0, 'windows_with_anomalies': 0}
        
        total_windows = len(self.detections)
        windows_with_anomalies = sum(1 for d in self.detections if d['anomaly_count'] > 0)
        total_anomalies = sum(d['anomaly_count'] for d in self.detections)
        
        # Aggregate by type and severity
        by_type = {}
        by_severity = {'medium': 0, 'high': 0}
        
        for detection in self.detections:
            for anom in detection['anomalies']:
                anom_type = anom.get('type', 'unknown')
                severity = anom.get('severity', 'medium')
                
                if anom_type not in by_type:
                    by_type[anom_type] = {'count': 0, 'medium': 0, 'high': 0}
                
                by_type[anom_type]['count'] += 1
                by_type[anom_type][severity] += 1
                by_severity[severity] += 1
        
        return {
            'total_windows': total_windows,
            'windows_with_anomalies': windows_with_anomalies,
            'anomaly_percentage': round(100.0 * windows_with_anomalies / total_windows, 2),
            'total_anomalies': total_anomalies,
            'by_type': by_type,
            'by_severity': by_severity,
        }


def main():
    """Test the anomaly engine."""
    engine = AnomalyEngine()
    
    print("=" * 70)
    print("Network Traffic Anomaly Detection Engine")
    print("=" * 70)
    
    # Batch analyze all metrics
    results = engine.batch_analyze()
    
    # Export results
    engine.export_detections()
    
    # Print statistics
    stats = engine.get_statistics()
    print("\n" + "=" * 70)
    print("Anomaly Detection Summary")
    print("=" * 70)
    print(f"Total windows analyzed: {stats['total_windows']}")
    print(f"Windows with anomalies: {stats['windows_with_anomalies']} "
          f"({stats['anomaly_percentage']}%)")
    print(f"Total anomalies detected: {stats['total_anomalies']}")
    print("\nAnomalies by type:")
    for anom_type, type_stats in stats['by_type'].items():
        print(f"  {anom_type}: {type_stats['count']} "
              f"(medium: {type_stats['medium']}, high: {type_stats['high']})")
    print(f"\nBy severity: Medium: {stats['by_severity']['medium']}, "
          f"High: {stats['by_severity']['high']}")
    print("=" * 70)


if __name__ == "__main__":
    main()
