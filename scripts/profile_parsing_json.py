import os
import time
import pyshark


def get_pcap_path():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), '../data/raw/pcapng/test_net_traffic.pcapng'))


def profile():
    pcap = get_pcap_path()
    print(f"PCAP: {pcap}")

    # Measure capture initialization with JSON mode and not keeping packets
    t0 = time.time()
    capture = pyshark.FileCapture(pcap, display_filter='', use_json=True, keep_packets=False)
    t1 = time.time()
    print(f"Capture init time (json, no-keep): {t1 - t0:.3f} s")

    # Quick iterate: count packets without accessing fields
    count = 0
    t2 = time.time()
    for _ in capture:
        count += 1
    t3 = time.time()
    print(f"Iterate-only (json): counted {count} packets in {t3 - t2:.3f} s (avg {(t3-t2)/max(count,1):.6f} s/packet)")

    capture.close()

    # Iterate with field access (JSON provides similar fields)
    capture2 = pyshark.FileCapture(pcap, display_filter='', use_json=True, keep_packets=False)
    count2 = 0
    t4 = time.time()
    for pkt in capture2:
        try:
            _ = pkt.sniff_time
            if 'IP' in pkt:
                _ = pkt.ip.src
                _ = pkt.ip.dst
            if 'UDP' in pkt:
                _ = pkt.udp.srcport
        except Exception:
            pass
        count2 += 1
    t5 = time.time()
    capture2.close()
    print(f"Iterate+fields (json): counted {count2} packets in {t5 - t4:.3f} s (avg {(t5-t4)/max(count2,1):.6f} s/packet)")


if __name__ == '__main__':
    profile()
