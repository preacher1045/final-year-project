#!/usr/bin/env python3
"""
Protocol Anomaly Detection

Rule E: Detect unusual or unexpected protocol behavior.

Detection Rule:
  |P_current - P_normal| > 30%

Where:
  - P_normal = historical average protocol share
  - P_current = protocol share in the current window

Example: UDP traffic increases from 10% to 50% of total traffic.
"""

from typing import Dict, List, Any


class ProtocolAnomalyDetector:
    """Detects abnormal protocol usage patterns."""
    
    def __init__(self, protocol_baseline: Dict[str, Any]):
        """
        Initialize with protocol baseline.
        
        Args:
            protocol_baseline: Loaded baseline_protocols.json
        """
        self.baseline = protocol_baseline
        self.name = "protocol_anomaly"
        self.deviation_threshold = 30.0  # percent
    
    def detect(self, metric_window: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze metric window for abnormal protocol usage.
        
        Args:
            metric_window: Single window from metrics JSONL
        
        Returns:
            List of anomaly records (empty if no anomalies)
        """
        anomalies = []
        
        protocol_data = metric_window.get('protocol', {})
        current_dist = protocol_data.get('percentages', {})
        
        if not current_dist:
            return anomalies
        
        # Get baseline distribution
        baseline_dist = self.baseline.get('protocol_distribution', {})
        
        # Check each protocol in current distribution
        for proto_id, current_percent in current_dist.items():
            baseline_record = baseline_dist.get(str(proto_id), {})
            baseline_percent = baseline_record.get('percentage', 0)
            
            # Calculate absolute deviation
            deviation = abs(current_percent - baseline_percent)
            
            # Check if deviation exceeds threshold
            if deviation > self.deviation_threshold:
                severity = 'high' if deviation > self.deviation_threshold * 1.5 else 'medium'
                
                direction = 'increased' if current_percent > baseline_percent else 'decreased'
                percent_change = round(100 * (current_percent - baseline_percent) / max(baseline_percent, 1), 1)
                
                anomalies.append({
                    'type': self.name,
                    'severity': severity,
                    'metric': 'protocol_distribution',
                    'protocol_id': proto_id,
                    'current_percent': round(current_percent, 2),
                    'baseline_percent': round(baseline_percent, 2),
                    'deviation': round(deviation, 2),
                    'deviation_threshold': self.deviation_threshold,
                    'direction': direction,
                    'percent_change': f'{percent_change}%',
                    'message': f'Abnormal {proto_id} usage: {round(current_percent, 1)}% '
                               f'(baseline: {round(baseline_percent, 1)}%, deviation: {round(deviation, 1)}%)',
                })
        
        return anomalies
