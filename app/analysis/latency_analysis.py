from typing import List, Dict, Any
import statistics
import math
from datetime import datetime


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


def _percentiles(data, percentiles=(50, 90, 99)):
    if not data:
        return {p: None for p in percentiles}
    data_sorted = sorted(data)
    n = len(data_sorted)
    res = {}
    for p in percentiles:
        k = (p / 100) * (n - 1)
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            res[p] = data_sorted[int(k)]
        else:
            d0 = data_sorted[int(f)] * (c - k)
            d1 = data_sorted[int(c)] * (k - f)
            res[p] = d0 + d1
    return res


def estimate_tcp_rtt(records: List[Dict[str, Any]], max_window: float = 5.0) -> Dict[str, Any]:
    """
    Estimate TCP RTTs using SYN -> SYN-ACK exchanges.

    Returns stats: count, mean, median, percentiles, sample_rtts
    """
    # collect SYNs keyed by 4-tuple
    syns = {}
    rtts = []

    for r in records:
        flags = r.get('flags')
        if flags is None:
            continue
        # parse hex or decimal
        try:
            f = int(str(flags), 0)
        except Exception:
            # try to extract hex digits
            try:
                f = int(str(flags).strip(), 0)
            except Exception:
                continue
        ts = _to_ts(r.get('timestamp'))
        if ts is None:
            continue
        src = r.get('src_ip')
        dst = r.get('dst_ip')
        sport = r.get('src_port')
        dport = r.get('dst_port')

        if src is None or dst is None or sport is None or dport is None:
            continue

        syn_flag = bool(f & 0x02)
        ack_flag = bool(f & 0x10)

        key = (src, dst, str(sport), str(dport))
        rev_key = (dst, src, str(dport), str(sport))

        if syn_flag and not ack_flag:
            # SYN
            syns[key] = ts
        elif syn_flag and ack_flag:
            # SYN-ACK, match reverse SYN
            if rev_key in syns:
                t_syn = syns.pop(rev_key)
                if 0 <= (ts - t_syn) <= max_window:
                    rtts.append(ts - t_syn)

    stats = {}
    stats['count'] = len(rtts)
    if rtts:
        stats['mean'] = statistics.mean(rtts)
        stats['median'] = statistics.median(rtts)
        stats['percentiles'] = _percentiles(rtts, (50, 90, 99))
        stats['sample_rtts'] = rtts[:100]
    else:
        stats['mean'] = stats['median'] = None
        stats['percentiles'] = {50: None, 90: None, 99: None}
        stats['sample_rtts'] = []

    return stats


def estimate_request_response(records: List[Dict[str, Any]], max_window: float = 5.0) -> Dict[str, Any]:
    """
    Generic request-response latency estimation: for each packet, attempt to find the next packet
    in the reverse direction (dst->src, ports swapped) within max_window seconds and measure latency.

    Returns aggregated stats (count, mean, median, percentiles)
    """
    # group by 4-tuple in forward direction
    pending = {}
    latencies = []

    # sort records by timestamp
    recs = []
    for r in records:
        ts = _to_ts(r.get('timestamp'))
        if ts is None:
            continue
        r2 = dict(r)
        r2['_ts'] = ts
        recs.append(r2)
    recs.sort(key=lambda x: x['_ts'])

    for r in recs:
        ts = r['_ts']
        src = r.get('src_ip')
        dst = r.get('dst_ip')
        sport = r.get('src_port')
        dport = r.get('dst_port')
        if not src or not dst or sport is None or dport is None:
            continue
        key = (src, dst, str(sport), str(dport))
        rev_key = (dst, src, str(dport), str(sport))

        # If there is a pending request in reverse direction, this is a response for it
        if rev_key in pending:
            req_ts = pending.pop(rev_key)
            delta = ts - req_ts
            if 0 <= delta <= max_window:
                latencies.append(delta)
            continue

        # otherwise register this as pending request
        # we keep only the earliest pending per tuple
        if key not in pending:
            pending[key] = ts

    stats = {'count': len(latencies)}
    if latencies:
        stats['mean'] = statistics.mean(latencies)
        stats['median'] = statistics.median(latencies)
        stats['percentiles'] = _percentiles(latencies, (50, 90, 99))
        stats['sample_latencies'] = latencies[:100]
    else:
        stats['mean'] = stats['median'] = None
        stats['percentiles'] = {50: None, 90: None, 99: None}
        stats['sample_latencies'] = []

    return stats


def compute_latency_metrics(records: List[Dict[str, Any]], max_window: float = 5.0) -> Dict[str, Any]:
    """
    Compute a set of latency-related metrics from normalized records.
    Returns dict with 'tcp_rtt' and 'req_rsp' subkeys.
    """
    tcp = estimate_tcp_rtt(records, max_window=max_window)
    req = estimate_request_response(records, max_window=max_window)
    return {'tcp_rtt': tcp, 'request_response': req}
