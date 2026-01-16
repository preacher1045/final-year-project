import pyshark
from ..capture.pcap_loader import get_raw_data_path


def parse_udp_packets(pcap_file: str):
    """
    Parse UDP packets from a PCAP file.

    Args:
        pcap_file (str): Path to the PCAP file.
    Returns:
        list: List of parsed UDP packets.
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
        capture = pyshark.FileCapture(pcap_path, display_filter='udp', use_json=True, keep_packets=False)
        udp_packets = []

        for packet in capture:
            if 'UDP' in packet:
                try:
                    ip_layer = packet.ip if 'IP' in packet else None
                    udp_layer = packet.udp
                    frame_info = {
                        'timestamp': packet.sniff_time.isoformat(),
                        'src_ip': ip_layer.src if ip_layer else None,
                        'dst_ip': ip_layer.dst if ip_layer else None,
                        'src_port': udp_layer.srcport,
                        'dst_port': udp_layer.dstport,
                        'length': udp_layer.length,
                    }
                    udp_packets.append(frame_info)
                except AttributeError:
                    continue

        capture.close()
        print(f"Parsed {len(udp_packets)} UDP packets from {pcap_file}")
        return udp_packets   
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
    udp_packets = parse_udp_packets(pcap_file)
    end_time = time.time()
    
    elapsed_time = end_time - start_time
    print(f"\nParsing completed in {elapsed_time:.2f} seconds")
    
    if udp_packets:
        print(f"\nFirst UDP packet details:")
        for key, value in udp_packets[0].items():
            print(f"  {key}: {value}")
    print(f"Total UDP packets parsed: {len(udp_packets)}")

