from typing import List, Dict, Any
from collections import Counter, defaultdict
from datetime import datetime
import math


def _to_ts(ts):
    if ts is None:
        return None
    try:
        return float(ts)
    except Exception:
        try:
            return datetime.fromisoformat(ts).timestamp()
        except Exception:
            return None


def compute_bandwidth_metrics(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Compute overall bandwidth metrics from normalized records.

    Returns:
      - total_bytes
      - total_packets
      - duration_s (if timestamps available)
      - avg_bps
      - avg_pps
      - top_src_bytes (list of (src_ip, bytes))
      - top_dst_bytes (list of (dst_ip, bytes))
    """
    total_bytes = 0
    total_packets = 0
    times = []
    src_bytes = Counter()
    dst_bytes = Counter()

    for r in records:
        size = 0
        try:
            if r.get('length') is not None:
                size = int(r.get('length'))
        except Exception:
            size = 0
        total_bytes += size
        total_packets += 1

        if r.get('src_ip'):
            src_bytes[r['src_ip']] += size
        if r.get('dst_ip'):
            dst_bytes[r['dst_ip']] += size

        ts = _to_ts(r.get('timestamp'))
        if ts is not None:
            times.append(ts)

    duration = None
    if times:
        duration = max(times) - min(times) if len(times) > 1 else 0.0

    avg_bps = None
    avg_pps = None
    if duration and duration > 0:
        avg_bps = total_bytes / duration
        avg_pps = total_packets / duration

    return {
        'total_bytes': total_bytes,
        'total_packets': total_packets,
        'duration_s': duration,
        'avg_bps': avg_bps,
        'avg_pps': avg_pps,
        'top_src_bytes': src_bytes.most_common(10),
        'top_dst_bytes': dst_bytes.most_common(10),
    }


def compute_bandwidth_per_window(records: List[Dict[str, Any]], window_seconds: int = 10) -> List[Dict[str, Any]]:
    """
    Window records by `window_seconds` and compute bandwidth metrics per window.

    Returns a list of metric dicts with keys: window_start, window_end, total_bytes, total_packets, avg_bps, avg_pps
    """
    norm = []
    for r in records:
        ts = _to_ts(r.get('timestamp'))
        if ts is None:
            continue
        r2 = dict(r)
        r2['_ts'] = ts
        norm.append(r2)

    if not norm:
        return []

    norm.sort(key=lambda x: x['_ts'])
    start = norm[0]['_ts']
    end = norm[-1]['_ts']

    windows = []
    window_start = start
    while window_start <= end:
        window_end = window_start + window_seconds
        bucket = [r for r in norm if window_start <= r['_ts'] < window_end]
        total_bytes = sum(int(r.get('length') or 0) if r.get('length') is not None else 0 for r in bucket)
        total_packets = len(bucket)
        avg_bps = (total_bytes / window_seconds) if window_seconds > 0 else None
        avg_pps = (total_packets / window_seconds) if window_seconds > 0 else None

        windows.append({
            'window_start': window_start,
            'window_end': window_end,
            'total_bytes': total_bytes,
            'total_packets': total_packets,
            'avg_bps': avg_bps,
            'avg_pps': avg_pps,
        })

        window_start = window_end

    return windows
