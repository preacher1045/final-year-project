#!/usr/bin/env python3
"""
Flow Enrichment Module

Extracts flow-level metrics from raw PCAP data to support advanced anomaly detection.
Produces per-flow statistics including:
- TCP SYN packet counts (for port scan detection)
- Unique destination ports per source IP
- Retransmission counts (for packet loss detection)
- Connection state tracking (established, reset, etc.)

Used by:
- scan_detector.py (port scanning detection)
- packet_loss_detection.py (reliability monitoring)
"""

import pyshark
from typing import Dict, List, Any, Set, Tuple
from collections import defaultdict


class FlowEnricher:
    """Extract per-flow metrics from PCAP data for advanced detection."""
    
    def __init__(self, pcap_path: str):
        """
        Initialize flow enricher.
        
        Args:
            pcap_path: Path to PCAP file
        """
        self.pcap_path = pcap_path
    
    def extract_flows(self) -> List[Dict[str, Any]]:
        """
        Extract all flows from PCAP and return list of flow records.
        
        Returns:
            List of flow dicts with src_ip, dst_ip, src_port, dst_port, etc.
        """
        flows = []
        flow_map = {}  # (src_ip, src_port, dst_ip, dst_port, protocol) -> flow data
        
        try:
            cap = pyshark.FileCapture(
                self.pcap_path,
                use_json=True,
                keep_packets=False,
                only_summaries=False
            )
            
            for packet in cap:
                flow_data = self._extract_flow_from_packet(packet)
                if not flow_data:
                    continue
                
                # Use 5-tuple as flow key (src_ip, src_port, dst_ip, dst_port, protocol)
                flow_key = (
                    flow_data.get('src_ip'),
                    flow_data.get('src_port'),
                    flow_data.get('dst_ip'),
                    flow_data.get('dst_port'),
                    flow_data.get('protocol')
                )
                
                if flow_key not in flow_map:
                    flow_map[flow_key] = {
                        'src_ip': flow_data['src_ip'],
                        'src_port': flow_data['src_port'],
                        'dst_ip': flow_data['dst_ip'],
                        'dst_port': flow_data['dst_port'],
                        'protocol': flow_data['protocol'],
                        'packet_count': 0,
                        'byte_count': 0,
                        'syn_count': 0,
                        'ack_count': 0,
                        'rst_count': 0,
                        'fin_count': 0,
                        'retransmission_count': 0,
                        'last_seq': None,
                        'last_ack': None,
                    }
                
                # Update flow statistics
                flow = flow_map[flow_key]
                flow['packet_count'] += 1
                flow['byte_count'] += flow_data.get('length', 0)
                
                # Track TCP flags for scan detection
                if flow_data.get('flags'):
                    flags = flow_data['flags']
                    if 'SYN' in flags or flags == '0x0002':
                        flow['syn_count'] += 1
                    if 'ACK' in flags or '0x0010' in flags:
                        flow['ack_count'] += 1
                    if 'RST' in flags or flags == '0x0004':
                        flow['rst_count'] += 1
                    if 'FIN' in flags or flags == '0x0001':
                        flow['fin_count'] += 1
                
                # Detect retransmissions (same sequence number sent twice)
                if flow_data.get('seq') is not None:
                    if flow['last_seq'] == flow_data['seq']:
                        flow['retransmission_count'] += 1
                    flow['last_seq'] = flow_data['seq']
            
            cap.close()
            flows = list(flow_map.values())
        
        except Exception as e:
            print(f"Error extracting flows: {e}")
        
        return flows
    
    def _extract_flow_from_packet(self, packet) -> Dict[str, Any]:
        """
        Extract flow information from a single packet.
        
        Returns:
            Dict with src_ip, dst_ip, src_port, dst_port, protocol, flags, seq, etc.
            or None if not a TCP/UDP packet
        """
        try:
            # Get IP layer
            if 'IP' in packet:
                ip_layer = packet['IP']
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            elif 'IPv6' in packet:
                ip_layer = packet['IPv6']
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
            else:
                return None
            
            # Get protocol-specific info
            protocol = None
            src_port = None
            dst_port = None
            flags = None
            seq = None
            ack = None
            length = 0
            
            if 'TCP' in packet:
                tcp_layer = packet['TCP']
                protocol = 'TCP'
                src_port = int(tcp_layer.srcport) if hasattr(tcp_layer, 'srcport') else None
                dst_port = int(tcp_layer.dstport) if hasattr(tcp_layer, 'dstport') else None
                
                # Extract TCP flags
                if hasattr(tcp_layer, 'flags'):
                    flags = tcp_layer.flags
                
                # Extract sequence numbers for retransmission detection
                if hasattr(tcp_layer, 'seq'):
                    seq = int(tcp_layer.seq)
                if hasattr(tcp_layer, 'ack'):
                    ack = int(tcp_layer.ack)
                
                length = int(tcp_layer.len) if hasattr(tcp_layer, 'len') else 0
            
            elif 'UDP' in packet:
                udp_layer = packet['UDP']
                protocol = 'UDP'
                src_port = int(udp_layer.srcport) if hasattr(udp_layer, 'srcport') else None
                dst_port = int(udp_layer.dstport) if hasattr(udp_layer, 'dstport') else None
                length = int(udp_layer.len) if hasattr(udp_layer, 'len') else 0
            
            else:
                return None
            
            if not protocol or src_port is None or dst_port is None:
                return None
            
            return {
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'src_port': src_port,
                'dst_port': dst_port,
                'protocol': protocol,
                'flags': flags,
                'seq': seq,
                'ack': ack,
                'length': length,
            }
        
        except Exception:
            return None
    
    def extract_source_port_scan_activity(self) -> List[Dict[str, Any]]:
        """
        Extract per-source-IP statistics for port scan detection.
        
        Returns:
            List of records:
            {
              'src_ip': str,
              'syn_count': int,
              'unique_dst_ports': int,
              'dst_ports': [list of ports],
              'total_packets': int,
              'has_responses': bool (if any ACKs received)
            }
        """
        flows = self.extract_flows()
        
        # Aggregate by source IP
        src_stats = defaultdict(lambda: {
            'syn_count': 0,
            'dst_ports': set(),
            'total_packets': 0,
            'has_responses': False,
        })
        
        for flow in flows:
            src_ip = flow['src_ip']
            src_stats[src_ip]['syn_count'] += flow['syn_count']
            src_stats[src_ip]['dst_ports'].add(flow['dst_port'])
            src_stats[src_ip]['total_packets'] += flow['packet_count']
            if flow['ack_count'] > 0:
                src_stats[src_ip]['has_responses'] = True
        
        # Convert to list
        results = []
        for src_ip, stats in src_stats.items():
            results.append({
                'src_ip': src_ip,
                'syn_count': stats['syn_count'],
                'unique_dst_ports': len(stats['dst_ports']),
                'dst_ports': sorted(list(stats['dst_ports'])),
                'total_packets': stats['total_packets'],
                'has_responses': stats['has_responses'],
            })
        
        return results
    
    def extract_retransmission_stats(self) -> List[Dict[str, Any]]:
        """
        Extract per-flow retransmission statistics for packet loss detection.
        
        Returns:
            List of records:
            {
              'src_ip': str,
              'dst_ip': str,
              'src_port': int,
              'dst_port': int,
              'protocol': str,
              'packet_count': int,
              'retransmission_count': int,
              'retransmission_rate': float (percent)
            }
        """
        flows = self.extract_flows()
        
        results = []
        for flow in flows:
            if flow['protocol'] == 'TCP' and flow['packet_count'] > 0:
                retrans_rate = 100.0 * flow['retransmission_count'] / flow['packet_count']
                
                results.append({
                    'src_ip': flow['src_ip'],
                    'dst_ip': flow['dst_ip'],
                    'src_port': flow['src_port'],
                    'dst_port': flow['dst_port'],
                    'protocol': flow['protocol'],
                    'packet_count': flow['packet_count'],
                    'retransmission_count': flow['retransmission_count'],
                    'retransmission_rate': round(retrans_rate, 2),
                })
        
        # Sort by retransmission rate (descending)
        results.sort(key=lambda x: x['retransmission_rate'], reverse=True)
        
        return results


def main():
    """Test flow enrichment."""
    pcap_path = "data/raw/pcapng/test_net_traffic.pcapng"
    
    print("=" * 70)
    print("Flow Enrichment Analysis")
    print("=" * 70)
    
    enricher = FlowEnricher(pcap_path)
    
    # Extract port scan activity
    print("\n1. Port Scan Detection Candidates:")
    print("-" * 70)
    scan_activity = enricher.extract_source_port_scan_activity()
    
    # Show top sources by SYN count
    scan_activity.sort(key=lambda x: x['syn_count'], reverse=True)
    for src in scan_activity[:10]:
        if src['syn_count'] > 5:
            print(f"  {src['src_ip']:15} — "
                  f"SYNs: {src['syn_count']:3}, "
                  f"Ports: {src['unique_dst_ports']:3}, "
                  f"Packets: {src['total_packets']:5}, "
                  f"Responses: {src['has_responses']}")
    
    # Extract retransmission stats
    print("\n2. Packet Loss (Retransmission) Detection:")
    print("-" * 70)
    retrans_stats = enricher.extract_retransmission_stats()
    
    # Show top flows by retransmission rate
    for flow in retrans_stats[:10]:
        if flow['retransmission_rate'] > 0:
            print(f"  {flow['src_ip']:15}:{flow['src_port']:5} → "
                  f"{flow['dst_ip']:15}:{flow['dst_port']:5} "
                  f"Retrans Rate: {flow['retransmission_rate']:5.2f}% "
                  f"({flow['retransmission_count']}/{flow['packet_count']})")
    
    print("\n" + "=" * 70)


if __name__ == "__main__":
    main()
