# #!/usr/bin/env python3
# """
# Live Packet Capture & Real-Time Anomaly Detection

# Captures packets from a network interface or PCAP file in real-time,
# computes metrics in sliding windows, and detects anomalies with minimal latency.

# Features:
# - Real-time windowed metric computation
# - Ring buffer for bounded memory usage
# - Integrated anomaly detection per window
# - Logging of detected anomalies
# - Graceful shutdown handling
# """

# import argparse
# import json
# import os
# import signal
# import sys
# import time
# from collections import deque
# from typing import Dict, List, Any, Optional
# from datetime import datetime
# import pyshark

# from app.analysis.traffic_metric import (
#     normalize_record, deduplicate_records, compute_metrics
# )
# from app.analysis.bandwidth_analysis import compute_bandwidth_metrics
# from app.analysis.latency_analysis import compute_latency_metrics
# from app.analysis.connection_analysis import compute_connection_metrics
# from app.analysis.protocol_distribution import compute_protocol_distribution
# from app.anomalies.anomaly_engine import AnomalyEngine
# from app.main import log_analysis_start, log_anomaly_detection, log_anomaly_window_summary
# from app.main import setup_logging


# class RingBuffer:
#     """Fixed-size circular buffer for memory-bounded packet storage."""
    
#     def __init__(self, max_size: int = 100000):
#         """
#         Initialize ring buffer.
        
#         Args:
#             max_size: Maximum number of packets to store
#         """
#         self.max_size = max_size
#         self.buffer = deque(maxlen=max_size)
#         self.packet_count = 0
#         self.dropped_packets = 0
    
#     def append(self, packet_data: Dict[str, Any]) -> None:
#         """Add packet to buffer (automatically evicts oldest if full)."""
#         if len(self.buffer) >= self.max_size:
#             self.dropped_packets += 1
#         self.buffer.append(packet_data)
#         self.packet_count += 1
    
#     def get_all(self) -> List[Dict[str, Any]]:
#         """Get all packets in buffer."""
#         return list(self.buffer)
    
#     def clear(self) -> None:
#         """Clear buffer."""
#         self.buffer.clear()
    
#     def stats(self) -> Dict[str, Any]:
#         """Get buffer statistics."""
#         return {
#             'capacity': self.max_size,
#             'current_size': len(self.buffer),
#             'total_packets': self.packet_count,
#             'dropped_packets': self.dropped_packets,
#         }


# class LiveCapture:
#     """Real-time packet capture with windowed metric computation."""
    
#     def __init__(
#         self,
#         pcap_source: str,
#         window_seconds: int = 10,
#         ring_buffer_size: int = 100000,
#         enable_anomaly_detection: bool = True
#     ):
#         """
#         Initialize live capture.
        
#         Args:
#             pcap_source: Interface name (e.g. 'eth0') or PCAP file path
#             window_seconds: Metric computation window size
#             ring_buffer_size: Max packets to keep in memory
#             enable_anomaly_detection: Whether to run anomaly detection
#         """
#         self.pcap_source = pcap_source
#         self.window_seconds = window_seconds
#         self.ring_buffer = RingBuffer(ring_buffer_size)
#         self.enable_anomaly_detection = enable_anomaly_detection
#         self.anomaly_engine = AnomalyEngine() if enable_anomaly_detection else None
        
#         self.running = True
#         self.window_count = 0
#         self.window_start_time = None
#         self.results = []
        
#         # Setup signal handlers for graceful shutdown
#         signal.signal(signal.SIGINT, self._signal_handler)
#         signal.signal(signal.SIGTERM, self._signal_handler)
    
#     def _signal_handler(self, signum, frame) -> None:
#         """Handle shutdown signals gracefully."""
#         print("\n\nShutdown signal received. Finalizing...")
#         self.running = False
    
#     def _extract_packet_data(self, packet) -> Optional[Dict[str, Any]]:
#         """Extract relevant fields from packet."""
#         try:
#             # Get timestamp
#             timestamp = float(packet.frame_info.time_epoch) if hasattr(packet, 'frame_info') else time.time()
            
#             # Get basic info
#             src_ip = None
#             dst_ip = None
#             src_port = None
#             dst_port = None
#             protocol = None
#             length = 0
            
#             if 'IP' in packet:
#                 ip_layer = packet['IP']
#                 src_ip = ip_layer.src
#                 dst_ip = ip_layer.dst
#                 length = int(ip_layer.len) if hasattr(ip_layer, 'len') else 0
#             elif 'IPv6' in packet:
#                 ip_layer = packet['IPv6']
#                 src_ip = ip_layer.src
#                 dst_ip = ip_layer.dst
#                 length = int(ip_layer.plen) if hasattr(ip_layer, 'plen') else 0
            
#             if 'TCP' in packet:
#                 tcp = packet['TCP']
#                 protocol = 'TCP'
#                 src_port = int(tcp.srcport)
#                 dst_port = int(tcp.dstport)
#             elif 'UDP' in packet:
#                 udp = packet['UDP']
#                 protocol = 'UDP'
#                 src_port = int(udp.srcport)
#                 dst_port = int(udp.dstport)
            
#             if not protocol:
#                 return None
            
#             return {
#                 'timestamp': timestamp,
#                 'src_ip': src_ip,
#                 'dst_ip': dst_ip,
#                 'src_port': src_port,
#                 'dst_port': dst_port,
#                 'protocol': protocol,
#                 'length': length,
#             }
        
#         except Exception:
#             return None
    
#     def capture_and_analyze(self, duration: Optional[int] = None) -> List[Dict[str, Any]]:
#         """
#         Capture packets and compute metrics in windows.
        
#         Args:
#             duration: Max capture duration in seconds (None for continuous)
        
#         Returns:
#             List of windowed metric/anomaly results
#         """
#         setup_logging()
#         log_analysis_start()
        
#         start_time = time.time()
#         first_packet_time = None
#         window_start = None
        
#         print(f"\nCapturing from: {self.pcap_source}")
#         print(f"Window size: {self.window_seconds}s")
#         print(f"Ring buffer: {self.ring_buffer.max_size} packets")
#         print("-" * 70)
        
#         try:
#             # Determine if source is file or interface
#             is_file = os.path.isfile(self.pcap_source)
            
#             if is_file:
#                 cap = pyshark.FileCapture(
#                     self.pcap_source,
#                     use_json=True,
#                     keep_packets=False
#                 )
#             else:
#                 cap = pyshark.LiveCapture(
#                     interface=self.pcap_source,
#                     use_json=True,
#                     keep_packets=False
#                 )
            
#             for packet_num, packet in enumerate(cap):
#                 if not self.running:
#                     break
                
#                 # Check duration limit
#                 if duration and (time.time() - start_time) > duration:
#                     break
                
#                 # Extract packet data
#                 pkt_data = self._extract_packet_data(packet)
#                 if not pkt_data:
#                     continue
                
#                 # Initialize window timing from first packet
#                 if first_packet_time is None:
#                     first_packet_time = pkt_data['timestamp']
#                     window_start = first_packet_time
                
#                 # Add to buffer
#                 self.ring_buffer.append(pkt_data)
                
#                 # Check if time to compute window
#                 current_time = pkt_data['timestamp']
#                 if current_time >= window_start + self.window_seconds:
#                     # Compute metrics for this and previous windows
#                     while window_start + self.window_seconds <= current_time:
#                         window_end = window_start + self.window_seconds
#                         result = self._compute_window_metrics(window_start, window_end)
#                         if result:
#                             self.results.append(result)
#                             self.window_count += 1
#                             print(f"  Window {self.window_count}: "
#                                   f"{result['record_count']} records, "
#                                   f"{len(result.get('anomalies', []))} anomalies")
                        
#                         window_start = window_end
            
#             cap.close()
        
#         except KeyboardInterrupt:
#             print("\nInterrupted by user")
#         except Exception as e:
#             print(f"Capture error: {e}")
        
#         print("\n" + "=" * 70)
#         print(f"Capture complete: {self.window_count} windows, "
#               f"{self.ring_buffer.packet_count} packets total")
#         print(f"Memory usage: {self.ring_buffer.stats()}")
#         print("=" * 70)
        
#         return self.results
    
#     def _compute_window_metrics(
#         self,
#         window_start: float,
#         window_end: float
#     ) -> Optional[Dict[str, Any]]:
#         """Compute metrics for a time window."""
#         packets = self.ring_buffer.get_all()
        
#         if not packets:
#             return None
        
#         # Filter packets to window
#         window_packets = [
#             p for p in packets 
#             if window_start <= p['timestamp'] < window_end
#         ]
        
#         if not window_packets:
#             return None
        
#         # Normalize and deduplicate
#         norm = [normalize_record(p) for p in window_packets]
#         norm = deduplicate_records(norm)
        
#         # Compute metrics
#         metrics = compute_metrics(norm)
#         metrics['bandwidth'] = compute_bandwidth_metrics(norm)
#         metrics['latency'] = compute_latency_metrics(norm)
#         metrics['connections'] = compute_connection_metrics(norm)
#         metrics['protocol'] = compute_protocol_distribution(norm)
#         metrics['window_start'] = window_start
#         metrics['window_end'] = window_end
#         metrics['record_count'] = len(norm)
        
#         # Run anomaly detection if enabled
#         anomalies = []
#         if self.enable_anomaly_detection and self.anomaly_engine:
#             detection = self.anomaly_engine.analyze_metric_window(metrics)
#             anomalies = detection.get('anomalies', [])
#             metrics['anomalies'] = anomalies
        
#         # Log results
#         if anomalies:
#             log_anomaly_window_summary(
#                 self.window_count,
#                 anomalies,
#                 window_start,
#                 window_end
#             )
#             for anom in anomalies:
#                 log_anomaly_detection(anom, self.window_count)
        
#         return metrics
    
#     def export_results(self, output_file: str) -> None:
#         """Export results to JSONL file."""
#         os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        
#         with open(output_file, 'w') as f:
#             for result in self.results:
#                 f.write(json.dumps(result) + '\n')
        
#         print(f"\n✓ Exported {len(self.results)} windows to {output_file}")


# def main():
#     """Main entry point."""
#     parser = argparse.ArgumentParser(
#         description="Live packet capture with real-time anomaly detection"
#     )
#     parser.add_argument(
#         'source',
#         help='Network interface (e.g., eth0) or PCAP file path'
#     )
#     parser.add_argument(
#         '--window',
#         type=int,
#         default=10,
#         help='Window size in seconds (default: 10)'
#     )
#     parser.add_argument(
#         '--buffer',
#         type=int,
#         default=100000,
#         help='Ring buffer max packets (default: 100000)'
#     )
#     parser.add_argument(
#         '--duration',
#         type=int,
#         default=None,
#         help='Capture duration in seconds (None for continuous)'
#     )
#     parser.add_argument(
#         '--output',
#         default='logs/live_metrics.jsonl',
#         help='Output file path'
#     )
#     parser.add_argument(
#         '--no-anomaly',
#         action='store_true',
#         help='Disable anomaly detection'
#     )
    
#     args = parser.parse_args()
    
#     # Create capture instance
#     capture = LiveCapture(
#         args.source,
#         window_seconds=args.window,
#         ring_buffer_size=args.buffer,
#         enable_anomaly_detection=not args.no_anomaly
#     )
    
#     # Run capture
#     results = capture.capture_and_analyze(duration=args.duration)
    
#     # Export results
#     capture.export_results(args.output)


# if __name__ == '__main__':
#     main()
