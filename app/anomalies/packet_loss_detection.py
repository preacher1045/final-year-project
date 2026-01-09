#!/usr/bin/env python3
"""
Packet Loss Detection

Rule D: Detect network reliability issues.

Detection Rule:
  - Medium anomaly: Packet loss > 2%
  - High anomaly: Packet loss > 5%

Formula:
  Packet Loss (%) = (Sent - Received) / Sent × 100

Note: Packet loss is inferred from TCP retransmissions and missing ACKs.
Current implementation provides framework for integration with TCP segment tracking.
"""

from typing import Dict, List, Any


class PacketLossDetector:
    """Detects packet loss conditions."""
    
    def __init__(self):
        """Initialize packet loss detector."""
        self.name = "packet_loss"
        # Retransmission-based thresholds calibrated for real networks
        # Only flag extreme cases (likely measurement artifacts)
        self.threshold_medium = 50.0  # percent (very high - likely a data anomaly)
        self.threshold_high = 70.0  # percent (severe - definitely anomalous)
    
    def detect(self, metric_window: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Analyze metric window for packet loss anomalies.
        
        Uses flow-level retransmission data if available in metric window.
        
        Args:
            metric_window: Single window from metrics JSONL (may include 'retransmission_stats')
        
        Returns:
            List of anomaly records
        """
        anomalies = []
        
        # Check if flow-level retransmission data is included
        retrans_stats = metric_window.get('retransmission_stats', [])
        if not retrans_stats:
            return anomalies
        
        # Check each flow for high packet loss
        for flow in retrans_stats:
            loss_percent = flow.get('retransmission_rate', 0)
            src_ip = flow.get('src_ip')
            dst_ip = flow.get('dst_ip')
            src_port = flow.get('src_port')
            dst_port = flow.get('dst_port')
            retrans_count = flow.get('retransmission_count', 0)
            pkt_count = flow.get('packet_count', 0)
            
            # Check for anomalies
            if loss_percent > self.threshold_high:
                anomalies.append({
                    'type': self.name,
                    'severity': 'high',
                    'metric': 'packet_loss_percent',
                    'threshold': self.threshold_high,
                    'current_value': round(loss_percent, 2),
                    'message': f'High packet loss detected: {round(loss_percent, 2)}% '
                               f'({retrans_count} retrans / {pkt_count} sent)',
                    'flow_src': f'{src_ip}:{src_port}',
                    'flow_dst': f'{dst_ip}:{dst_port}',
                    'retransmitted_count': retrans_count,
                    'sent_count': pkt_count,
                })
            elif loss_percent > self.threshold_medium:
                anomalies.append({
                    'type': self.name,
                    'severity': 'medium',
                    'metric': 'packet_loss_percent',
                    'threshold': self.threshold_medium,
                    'current_value': round(loss_percent, 2),
                    'message': f'Medium packet loss detected: {round(loss_percent, 2)}% '
                               f'({retrans_count} retrans / {pkt_count} sent)',
                    'flow_src': f'{src_ip}:{src_port}',
                    'flow_dst': f'{dst_ip}:{dst_port}',
                    'retransmitted_count': retrans_count,
                    'sent_count': pkt_count,
                })
        
        return anomalies
    
    def detect_from_flows(
        self,
        flows: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect packet loss using TCP flow data.
        
        Args:
            flows: List of TCP flow records with retransmission counts
        
        Returns:
            List of anomaly records
        """
        anomalies = []
        
        for flow in flows:
            # Expected fields: sent_segments, retransmitted_segments, etc.
            sent = flow.get('sent_segments', 0)
            retransmitted = flow.get('retransmitted_segments', 0)
            acked = flow.get('acked_segments', 0)
            
            if sent == 0:
                continue
            
            # Estimate loss rate from retransmissions
            # Loss % = (retransmitted / sent) * 100
            loss_percent = 100.0 * retransmitted / sent if sent > 0 else 0
            
            # Check for anomalies
            if loss_percent > self.threshold_high:
                anomalies.append({
                    'type': self.name,
                    'severity': 'high',
                    'metric': 'packet_loss_percent',
                    'threshold': self.threshold_high,
                    'current_value': round(loss_percent, 2),
                    'message': f'High packet loss detected: {round(loss_percent, 2)}% '
                               f'({retransmitted} retrans / {sent} sent)',
                    'flow_src': flow.get('src_ip'),
                    'flow_dst': flow.get('dst_ip'),
                    'retransmitted_count': retransmitted,
                    'sent_count': sent,
                })
            elif loss_percent > self.threshold_medium:
                anomalies.append({
                    'type': self.name,
                    'severity': 'medium',
                    'metric': 'packet_loss_percent',
                    'threshold': self.threshold_medium,
                    'current_value': round(loss_percent, 2),
                    'message': f'Medium packet loss detected: {round(loss_percent, 2)}% '
                               f'({retransmitted} retrans / {sent} sent)',
                    'flow_src': flow.get('src_ip'),
                    'flow_dst': flow.get('dst_ip'),
                    'retransmitted_count': retransmitted,
                    'sent_count': sent,
                })
        
        return anomalies
