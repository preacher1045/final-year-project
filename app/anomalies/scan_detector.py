#!/usr/bin/env python3
"""
Scan Detector (Port Scanning / Excessive Connection Attempts)

Rule B: Detect port scanning activity or misconfigured applications.

Detection Conditions (both must be met):
  - SYN count > 100 within 60-second window
  - Destination ports contacted > 20

This detector needs flow-level data which requires enrichment from raw packets.
Current implementation provides the framework for integration.
"""

from typing import Dict, List, Any, Optional
from collections import defaultdict


class ScanDetector:
    """Detects port scanning activity."""
    
    def __init__(self):
        """Initialize scan detector."""
        self.name = "port_scan"
        self.syn_threshold = 100  # SYN packets
        self.port_threshold = 20  # Unique destination ports
        self.time_window = 60  # seconds
    
    def detect(self, metric_window: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze metric window for port scanning activity.
        
        Uses flow-level enrichment data if available in metric window.
        
        Args:
            metric_window: Single window from metrics JSONL (may include 'scan_activity')
        
        Returns:
            List of anomaly records
        """
        anomalies = []
        
        # Check if flow-level scan activity data is included
        scan_activity = metric_window.get('scan_activity', [])
        if not scan_activity:
            return anomalies
        
        # Check each source for port scanning indicators
        for src_activity in scan_activity:
            src_ip = src_activity.get('src_ip')
            syn_count = src_activity.get('syn_count', 0)
            port_count = src_activity.get('unique_dst_ports', 0)
            has_responses = src_activity.get('has_responses', False)
            
            # Both conditions must be met for high confidence detection
            if syn_count > self.syn_threshold and port_count > self.port_threshold:
                anomalies.append({
                    'type': self.name,
                    'severity': 'high',
                    'metric': 'port_scan_activity',
                    'source_ip': src_ip,
                    'syn_packet_count': syn_count,
                    'unique_dst_ports': port_count,
                    'threshold_syns': self.syn_threshold,
                    'threshold_ports': self.port_threshold,
                    'has_responses': has_responses,
                    'message': f'Port scan detected from {src_ip}: '
                               f'{syn_count} SYN packets to {port_count} unique ports',
                })
            elif syn_count > self.syn_threshold * 0.7 and port_count > self.port_threshold * 0.8:
                # Medium severity: close to thresholds
                anomalies.append({
                    'type': self.name,
                    'severity': 'medium',
                    'metric': 'port_scan_activity',
                    'source_ip': src_ip,
                    'syn_packet_count': syn_count,
                    'unique_dst_ports': port_count,
                    'threshold_syns': self.syn_threshold,
                    'threshold_ports': self.port_threshold,
                    'has_responses': has_responses,
                    'message': f'Possible port scan from {src_ip}: '
                               f'{syn_count} SYN packets to {port_count} unique ports',
                })
        
        return anomalies
    
    def detect_with_flows(
        self, 
        flows: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect port scans using flow-level data.
        
        Args:
            flows: List of flow records with src_ip, dst_port, tcp_flags, etc.
        
        Returns:
            List of anomaly records
        """
        anomalies = []
        
        # Track per-source activity
        src_syn_count = defaultdict(int)
        src_dst_ports = defaultdict(set)
        
        for flow in flows:
            src_ip = flow.get('src_ip')
            dst_port = flow.get('dst_port')
            flags = flow.get('flags', '')
            
            if not src_ip or dst_port is None:
                continue
            
            # Check for SYN flag (0x0002 or contains SYN string)
            is_syn = (flags == '0x0002' or 'SYN' in str(flags))
            
            if is_syn:
                src_syn_count[src_ip] += 1
            
            src_dst_ports[src_ip].add(str(dst_port))
        
        # Check for anomalies (both conditions)
        for src_ip, syn_count in src_syn_count.items():
            port_count = len(src_dst_ports.get(src_ip, set()))
            
            if syn_count > self.syn_threshold and port_count > self.port_threshold:
                anomalies.append({
                    'type': self.name,
                    'severity': 'high',
                    'metric': 'connection_attempts',
                    'source_ip': src_ip,
                    'syn_packet_count': syn_count,
                    'unique_dst_ports': port_count,
                    'threshold_syns': self.syn_threshold,
                    'threshold_ports': self.port_threshold,
                    'message': f'Port scan detected from {src_ip}: '
                               f'{syn_count} SYN packets to {port_count} unique ports',
                })
        
        return anomalies
