#!/usr/bin/env python3
"""
Long-Lived Connections Detection

Rule F: Detect stuck, idle, or suspiciously persistent sessions.

Detection Rules (environment-specific):
  - Session duration significantly exceeds baseline mean
  - Unusual combination of long duration + low throughput (idle detection)
  - Persistent connections to non-standard ports

Current implementation uses baseline statistics for thresholds.
"""

from typing import Dict, List, Any


class LongLivedConnectionDetector:
    """Detects suspicious long-lived or idle connections."""
    
    def __init__(self, connection_baseline: Dict[str, Any]):
        """
        Initialize with connection baseline.
        
        Args:
            connection_baseline: Loaded baseline_connections.json
        """
        self.baseline = connection_baseline
        self.name = "long_lived_conn"
        # Thresholds for suspicious behavior
        self.duration_multiplier = 2.0  # X times the baseline mean
        self.idle_bytes_threshold = 1000  # bytes for a "suspicious" long connection
    
    def detect(self, metric_window: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze metric window for long-lived connection anomalies.
        
        Args:
            metric_window: Single window from metrics JSONL
        
        Returns:
            List of anomaly records (empty if no anomalies)
        """
        anomalies = []
        
        connections = metric_window.get('connections', {})
        avg_duration = connections.get('avg_duration_s')
        avg_bytes = connections.get('avg_bytes_per_conn')
        total_attempts = connections.get('total_attempts', 0)
        
        if avg_duration is None:
            return anomalies
        
        # Get baseline
        baseline_duration = self.baseline.get('connection_duration_s', {})
        baseline_mean = baseline_duration.get('mean', avg_duration)
        baseline_max = baseline_duration.get('max', baseline_mean * 2)
        
        # Check for unusually long connections
        anomalies.extend(self._check_long_duration(
            avg_duration, baseline_mean, baseline_max, avg_bytes, total_attempts
        ))
        
        # Check for idle connections (long duration, few bytes)
        anomalies.extend(self._check_idle_connections(
            avg_duration, avg_bytes, baseline_mean
        ))
        
        return anomalies
    
    def _check_long_duration(
        self,
        avg_duration: float,
        baseline_mean: float,
        baseline_max: float,
        avg_bytes: float,
        total_attempts: int
    ) -> List[Dict[str, Any]]:
        """Check for abnormally long connection durations."""
        anomalies = []
        
        threshold_medium = baseline_mean * 1.5
        threshold_high = baseline_mean * self.duration_multiplier
        
        if avg_duration > threshold_high:
            anomalies.append({
                'type': self.name,
                'severity': 'high',
                'metric': 'connection_duration_s',
                'threshold': round(threshold_high, 4),
                'current_value': round(avg_duration, 4),
                'baseline_mean': round(baseline_mean, 4),
                'deviation': f"{round(100 * (avg_duration - baseline_mean) / baseline_mean, 1)}% above baseline",
                'message': f'Long-lived connections detected: avg {round(avg_duration, 2)}s duration '
                           f'(baseline: {round(baseline_mean, 2)}s)',
                'avg_bytes_per_conn': round(avg_bytes, 0) if avg_bytes else None,
                'connection_attempts': total_attempts,
            })
        elif avg_duration > threshold_medium:
            anomalies.append({
                'type': self.name,
                'severity': 'medium',
                'metric': 'connection_duration_s',
                'threshold': round(threshold_medium, 4),
                'current_value': round(avg_duration, 4),
                'baseline_mean': round(baseline_mean, 4),
                'deviation': f"{round(100 * (avg_duration - baseline_mean) / baseline_mean, 1)}% above baseline",
                'message': f'Moderately long connections detected: avg {round(avg_duration, 2)}s duration '
                           f'(baseline: {round(baseline_mean, 2)}s)',
                'avg_bytes_per_conn': round(avg_bytes, 0) if avg_bytes else None,
                'connection_attempts': total_attempts,
            })
        
        return anomalies
    
    def _check_idle_connections(
        self,
        avg_duration: float,
        avg_bytes: float,
        baseline_mean: float
    ) -> List[Dict[str, Any]]:
        """Check for idle (long duration, minimal data transfer)."""
        anomalies = []
        
        if avg_bytes is None:
            return anomalies
        
        # Idle connection: > 2x baseline duration but < idle_bytes_threshold bytes
        idle_threshold_duration = baseline_mean * 1.5
        
        if avg_duration > idle_threshold_duration and avg_bytes < self.idle_bytes_threshold:
            throughput = avg_bytes / avg_duration if avg_duration > 0 else 0
            
            anomalies.append({
                'type': self.name,
                'severity': 'medium',
                'metric': 'idle_connection',
                'current_duration_s': round(avg_duration, 2),
                'current_bytes': round(avg_bytes, 0),
                'throughput_bps': round(throughput, 2),
                'message': f'Idle or stuck connection detected: {round(avg_duration, 2)}s duration '
                           f'with only {round(avg_bytes, 0)} bytes transferred',
                'baseline_duration': round(baseline_mean, 2),
                'suspicion_reason': 'long_duration_low_throughput',
            })
        
        return anomalies
