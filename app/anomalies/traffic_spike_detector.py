#!/usr/bin/env python3
"""
Traffic Spike Detector

Rule A: Detect sudden increases in network bandwidth usage.
Uses rolling mean and standard deviation to identify anomalies.

Detection Rule:
  - Medium: Bₜ > μ + 2σ
  - High: Bₜ > μ + 3σ

Where:
  - Bₜ = current bandwidth (bytes per second)
  - μ = rolling mean (from baseline)
  - σ = rolling standard deviation (from baseline)
"""

from typing import Dict, List, Any, Optional


class TrafficSpikeDetector:
    """Detects sudden increases in bandwidth usage."""
    
    def __init__(self, bandwidth_baseline: Dict[str, Any]):
        """
        Initialize with bandwidth baseline.
        
        Args:
            bandwidth_baseline: Loaded baseline_bandwidth.json
        """
        self.baseline = bandwidth_baseline
        self.name = "traffic_spike"
    
    def detect(self, metric_window: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze metric window for traffic spikes.
        
        Args:
            metric_window: Single window from metrics JSONL
        
        Returns:
            List of anomaly records (empty if no anomalies)
        """
        anomalies = []
        
        # Extract current bandwidth
        bandwidth_data = metric_window.get('bandwidth', {})
        current_bps = bandwidth_data.get('avg_bps')
        
        if current_bps is None:
            return anomalies
        
        # Get baseline statistics
        bps_baseline = self.baseline.get('bytes_per_second', {})
        baseline_mean = bps_baseline.get('mean', 0)
        baseline_p99 = bps_baseline.get('p99', baseline_mean)
        
        # Estimate rolling mean and stddev from baseline rolling averages
        rolling_mean = bps_baseline.get('rolling_avg_mean', baseline_mean)
        rolling_max = bps_baseline.get('rolling_avg_max', baseline_p99)
        
        # Rough estimate of std dev from rolling range
        estimated_stddev = (rolling_max - rolling_mean) / 3 if rolling_max > rolling_mean else baseline_p99 * 0.1
        
        # Detection thresholds
        threshold_medium = rolling_mean + 2 * estimated_stddev
        threshold_high = rolling_mean + 3 * estimated_stddev
        
        # Check for anomalies
        if current_bps > threshold_high:
            anomalies.append({
                'type': self.name,
                'severity': 'high',
                'metric': 'bytes_per_second',
                'threshold': round(threshold_high, 2),
                'current_value': round(current_bps, 2),
                'deviation': f"{round(100 * (current_bps - rolling_mean) / rolling_mean, 1)}% above baseline",
                'message': f'High traffic spike detected: {round(current_bps, 0)} Bps (threshold: {round(threshold_high, 0)} Bps)',
                'baseline_mean': round(rolling_mean, 2),
                'baseline_stddev': round(estimated_stddev, 2),
            })
        elif current_bps > threshold_medium:
            anomalies.append({
                'type': self.name,
                'severity': 'medium',
                'metric': 'bytes_per_second',
                'threshold': round(threshold_medium, 2),
                'current_value': round(current_bps, 2),
                'deviation': f"{round(100 * (current_bps - rolling_mean) / rolling_mean, 1)}% above baseline",
                'message': f'Medium traffic spike detected: {round(current_bps, 0)} Bps (threshold: {round(threshold_medium, 0)} Bps)',
                'baseline_mean': round(rolling_mean, 2),
                'baseline_stddev': round(estimated_stddev, 2),
            })
        
        return anomalies
