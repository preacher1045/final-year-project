#!/usr/bin/env python3
"""
High Latency Detection

Rule C: Detect network congestion or performance degradation.

Detection Rule:
  - Medium: RTT_current > 1.5 × RTT_baseline
  - High: RTT_current > 2 × RTT_baseline

Where:
  - RTT_avg = baseline average RTT
  - RTT_current = current measured RTT
"""

from typing import Dict, List, Any


class LatencyAnomalyDetector:
    """Detects high latency conditions."""
    
    def __init__(self, latency_baseline: Dict[str, Any]):
        """
        Initialize with latency baseline.
        
        Args:
            latency_baseline: Loaded baseline_latency.json
        """
        self.baseline = latency_baseline
        self.name = "high_latency"
    
    def detect(self, metric_window: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze metric window for high latency anomalies.
        
        Checks both TCP RTT and request-response latencies.
        
        Args:
            metric_window: Single window from metrics JSONL
        
        Returns:
            List of anomaly records (empty if no anomalies)
        """
        anomalies = []
        
        latency_data = metric_window.get('latency', {})
        
        # Check TCP RTT
        anomalies.extend(self._check_tcp_rtt(latency_data))
        
        # Check request-response latency
        anomalies.extend(self._check_request_response(latency_data))
        
        return anomalies
    
    def _check_tcp_rtt(self, latency_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check TCP RTT for anomalies."""
        anomalies = []
        
        tcp_rtt = latency_data.get('tcp_rtt', {})
        current_rtt = tcp_rtt.get('mean')
        count = tcp_rtt.get('count', 0)
        
        if current_rtt is None or count == 0:
            return anomalies
        
        # Get baseline
        baseline_rtt = self.baseline.get('tcp_rtt_ms', {})
        baseline_mean = baseline_rtt.get('mean', current_rtt * 1000)  # Convert to ms
        
        # Convert current to ms if needed
        current_rtt_ms = current_rtt * 1000 if current_rtt < 1 else current_rtt
        
        # Detection thresholds
        threshold_medium = baseline_mean * 1.5
        threshold_high = baseline_mean * 2.0
        
        # Check for anomalies
        if current_rtt_ms > threshold_high:
            anomalies.append({
                'type': self.name,
                'severity': 'high',
                'metric': 'tcp_rtt_ms',
                'threshold': round(threshold_high, 2),
                'current_value': round(current_rtt_ms, 2),
                'deviation': f"{round(100 * (current_rtt_ms - baseline_mean) / baseline_mean, 1)}% above baseline",
                'message': f'High TCP RTT detected: {round(current_rtt_ms, 2)} ms (threshold: {round(threshold_high, 2)} ms)',
                'baseline_mean': round(baseline_mean, 2),
                'sample_count': count,
            })
        elif current_rtt_ms > threshold_medium:
            anomalies.append({
                'type': self.name,
                'severity': 'medium',
                'metric': 'tcp_rtt_ms',
                'threshold': round(threshold_medium, 2),
                'current_value': round(current_rtt_ms, 2),
                'deviation': f"{round(100 * (current_rtt_ms - baseline_mean) / baseline_mean, 1)}% above baseline",
                'message': f'Medium TCP RTT detected: {round(current_rtt_ms, 2)} ms (threshold: {round(threshold_medium, 2)} ms)',
                'baseline_mean': round(baseline_mean, 2),
                'sample_count': count,
            })
        
        return anomalies
    
    def _check_request_response(self, latency_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check request-response latency for anomalies."""
        anomalies = []
        
        req_resp = latency_data.get('request_response', {})
        current_latency = req_resp.get('mean')
        count = req_resp.get('count', 0)
        p99 = req_resp.get('percentiles', {}).get('99')
        
        if current_latency is None or count == 0:
            return anomalies
        
        # Get baseline
        baseline_latency = self.baseline.get('request_response_ms', {})
        baseline_mean = baseline_latency.get('mean', current_latency * 1000)  # Convert to ms
        baseline_p99 = baseline_latency.get('p99', baseline_mean * 2)
        
        # Convert current to ms if needed
        current_latency_ms = current_latency * 1000 if current_latency < 1 else current_latency
        
        # Detection thresholds
        threshold_medium = baseline_mean * 1.5
        threshold_high = baseline_mean * 2.0
        
        # Also check p99 for high variance
        p99_threshold = baseline_p99 * 1.5
        
        # Check for anomalies
        if current_latency_ms > threshold_high or (p99 and p99 > p99_threshold):
            anomalies.append({
                'type': self.name,
                'severity': 'high',
                'metric': 'request_response_ms',
                'threshold': round(threshold_high, 2),
                'current_value': round(current_latency_ms, 2),
                'deviation': f"{round(100 * (current_latency_ms - baseline_mean) / baseline_mean, 1)}% above baseline",
                'message': f'High request-response latency detected: {round(current_latency_ms, 2)} ms (threshold: {round(threshold_high, 2)} ms)',
                'baseline_mean': round(baseline_mean, 2),
                'p99': round(p99, 2) if p99 else None,
                'sample_count': count,
            })
        elif current_latency_ms > threshold_medium:
            anomalies.append({
                'type': self.name,
                'severity': 'medium',
                'metric': 'request_response_ms',
                'threshold': round(threshold_medium, 2),
                'current_value': round(current_latency_ms, 2),
                'deviation': f"{round(100 * (current_latency_ms - baseline_mean) / baseline_mean, 1)}% above baseline",
                'message': f'Medium request-response latency detected: {round(current_latency_ms, 2)} ms (threshold: {round(threshold_medium, 2)} ms)',
                'baseline_mean': round(baseline_mean, 2),
                'sample_count': count,
            })
        
        return anomalies
