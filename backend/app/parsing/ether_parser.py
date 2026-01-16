import pyshark
from ..capture.pcap_loader import get_raw_data_path


def parse_ethernet_frames(pcap_file: str):
    """
    Parse Ethernet frames from a PCAP file.

    Args:
        pcap_file (str): Path to the PCAP file.
    Returns:
        list: List of parsed Ethernet frames.
    """
    raw_data_path = get_raw_data_path()
    if not raw_data_path:
        print("Raw data path could not be determined.")
        return []

    # Check if pcap_file is a full path or just a filename
    if pcap_file.startswith('/') or '/' in pcap_file:
        pcap_path = pcap_file
    else:
        # Extract directory from raw_data_path and use that
        import os
        pcap_dir = os.path.dirname(raw_data_path)
        pcap_path = os.path.join(pcap_dir, pcap_file)
    try:
        capture = pyshark.FileCapture(pcap_path, display_filter='eth', use_json=True, keep_packets=False)
        ethernet_frames = []

        for packet in capture:
            if 'ETH' in packet:
                eth_layer = packet.eth
                # normalize fields for downstream metric computation
                src_ip = packet.ip.src if 'IP' in packet else None
                dst_ip = packet.ip.dst if 'IP' in packet else None
                src_port = None
                dst_port = None
                if 'UDP' in packet:
                    try:
                        src_port = packet.udp.srcport
                        dst_port = packet.udp.dstport
                    except Exception:
                        pass
                if 'TCP' in packet:
                    try:
                        src_port = packet.tcp.srcport
                        dst_port = packet.tcp.dstport
                    except Exception:
                        pass

                # try to obtain packet length if available
                pkt_len = None
                try:
                    pkt_len = int(packet.length)
                except Exception:
                    try:
                        # fallback to layer-specific lengths
                        if 'UDP' in packet and hasattr(packet.udp, 'length'):
                            pkt_len = int(packet.udp.length)
                    except Exception:
                        pkt_len = None

                frame_info = {
                    'timestamp': packet.sniff_time.isoformat(),
                    'src_mac': eth_layer.src,
                    'dst_mac': eth_layer.dst,
                    'eth_type': eth_layer.type,
                    'ip_layer': src_ip,
                    'udp_layer': src_port,
                    # canonical fields
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'src_port': src_port,
                    'dst_port': dst_port,
                    'length': pkt_len,
                }
                ethernet_frames.append(frame_info)

        capture.close()

        print(f"Parsed {len(ethernet_frames)} Ethernet frames from {pcap_file}")
        return ethernet_frames

    except FileNotFoundError:
        print(f"PCAP file not found: {pcap_path}")
        return []
    except Exception as e:
        print(f"Error parsing PCAP file: {e}")
        return []


if __name__ == '__main__':
    # Test the parser with the actual PCAP file from project data
    import os
    import time
    
    pcap_file = os.path.join(os.path.dirname(__file__), '../../data/raw/pcapng/test_net_traffic.pcapng')
    pcap_file = os.path.abspath(pcap_file)
    
    start_time = time.time()
    frames = parse_ethernet_frames(pcap_file)
    end_time = time.time()
    
    elapsed_time = end_time - start_time
    print(f"\nParsing completed in {elapsed_time:.2f} seconds")
    
    if frames:
        print(f"\nFirst frame details:")
        for key, value in frames[0].items():
            print(f"  {key}: {value}")
