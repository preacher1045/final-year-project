import pyshark
from ..capture.pcap_loader import get_raw_data_path


def parse_tcp_packets(pcap_file: str):
    """
    Parse TCP packets from a PCAP file.

    Args:
        pcap_file (str): Path to the PCAP file.
    Returns:
        list: List of parsed TCP packets.
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
        capture = pyshark.FileCapture(pcap_path, display_filter='tcp', use_json=True, keep_packets=False)
        tcp_packets = []

        for packet in capture:
            if 'TCP' in packet:
                ip_layer = packet.ip
                tcp_layer = packet.tcp
                frame_info = {
                    'timestamp': packet.sniff_time.isoformat(),
                    'src_ip': ip_layer.src,
                    'dst_ip': ip_layer.dst,
                    'src_port': tcp_layer.srcport,
                    'dst_port': tcp_layer.dstport,
                    'flags': tcp_layer.flags,
                    'seq': tcp_layer.seq,
                    'ack': tcp_layer.ack,
                }
                tcp_packets.append(frame_info)

        capture.close()
        print(f"Parsed {len(tcp_packets)} TCP packets from {pcap_file}")
        return tcp_packets   
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
    tcp_packets = parse_tcp_packets(pcap_file)
    end_time = time.time()
    
    elapsed_time = end_time - start_time
    print(f"\nParsing completed in {elapsed_time:.2f} seconds")
    
    if tcp_packets:
        print(f"\nFirst TCP packet details:")
        for key, value in tcp_packets[0].items():
            print(f"  {key}: {value}")
    print(f"Total TCP packets parsed: {len(tcp_packets)}")
