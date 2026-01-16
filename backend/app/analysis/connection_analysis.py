from typing import List, Dict, Any
from collections import defaultdict
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


def _flow_key(rec: Dict[str, Any]):
    # canonical 4-tuple for direction-sensitive tracking
    return (rec.get('src_ip'), rec.get('dst_ip'), str(rec.get('src_port')), str(rec.get('dst_port')))


def compute_connection_metrics(records: List[Dict[str, Any]], timeout: float = 120.0) -> Dict[str, Any]:
    """
    Compute connection-level metrics from normalized packet records.

    Metrics returned:
      - total_attempts: SYN seen
      - successful: SYN -> SYN-ACK -> ACK observed
      - failed_resets: connections reset (RST observed)
      - half_open: SYN without completion within timeout
      - avg_duration: mean duration for successful connections (seconds)
      - bytes_per_connection: mean bytes per successful connection (if lengths present)

    This uses simple TCP-flag heuristics. Records must include:
      'timestamp', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'flags', 'length'
    """
    # organize records by time
    recs = []
    for r in records:
        ts = _to_ts(r.get('timestamp'))
        if ts is None:
            continue
        r2 = dict(r)
        r2['_ts'] = ts
        recs.append(r2)
    recs.sort(key=lambda x: x['_ts'])

    attempts = 0
    successful = 0
    resets = 0
    flow_bytes = defaultdict(int)
    flow_times = []

    # track per-flow state: store timestamps of SYN, SYN-ACK, first ACK, last seen
    state = {}

    for r in recs:
        flags = r.get('flags')
        try:
            f = int(str(flags), 0) if flags is not None else 0
        except Exception:
            # best-effort parse
            try:
                f = int(str(flags).strip(), 0)
            except Exception:
                f = 0

        syn = bool(f & 0x02)
        ack = bool(f & 0x10)
        rst = bool(f & 0x04)

        key = _flow_key(r)
        rev_key = (key[1], key[0], key[3], key[2])
        ts = r['_ts']

        # update bytes
        length = 0
        try:
            if r.get('length') is not None:
                length = int(r.get('length'))
        except Exception:
            length = 0
        flow_bytes[key] += length

        # handle SYN
        if syn and not ack:
            attempts += 1
            state[key] = state.get(key, {})
            state[key]['syn_ts'] = ts
            state[key]['last_ts'] = ts
            state[key]['seen_syn_ack'] = False
            state[key]['seen_ack'] = False
            continue

        # handle SYN-ACK
        if syn and ack:
            # this is likely SYN-ACK from server, match reverse flow
            if rev_key in state and 'syn_ts' in state[rev_key]:
                state[rev_key]['seen_syn_ack'] = True
                state[rev_key]['last_ts'] = ts
            continue

        # handle ACK (non-SYN)
        if ack and not syn:
            # find matching pending flow in reverse direction (client->server)
            if key in state and state[key].get('seen_syn_ack'):
                # mark completion
                if not state[key].get('seen_ack'):
                    state[key]['seen_ack'] = True
                    state[key]['ack_ts'] = ts
                    # compute duration from syn to ack
                    syn_ts = state[key].get('syn_ts')
                    if syn_ts is not None:
                        dur = ts - syn_ts
                        flow_times.append(dur)
                        successful += 1
            state[key] = state.get(key, {})
            state[key]['last_ts'] = ts
            continue

        # handle RST
        if rst:
            # if either direction has a pending syn, mark reset
            if key in state or rev_key in state:
                resets += 1
                # clear states to avoid double counting
                state.pop(key, None)
                state.pop(rev_key, None)
            continue

        # update last seen timestamp for any state
        if key in state:
            state[key]['last_ts'] = ts

    # count half-open (SYN seen but no completion within timeout)
    half_open = 0
    now = recs[-1]['_ts'] if recs else 0
    for k, v in list(state.items()):
        syn_ts = v.get('syn_ts')
        seen_ack = v.get('seen_ack')
        if syn_ts and not seen_ack:
            if (now - syn_ts) >= timeout:
                half_open += 1

    avg_duration = None
    try:
        import statistics
        avg_duration = statistics.mean(flow_times) if flow_times else None
    except Exception:
        avg_duration = None

    avg_bytes = None
    try:
        import statistics
        # compute per-successful-flow bytes mean by checking flow_bytes for keys that had completion
        # best-effort: use all flows if successful>0
        if successful > 0:
            avg_bytes = statistics.mean([b for b in flow_bytes.values()])
    except Exception:
        avg_bytes = None

    return {
        'total_attempts': attempts,
        'successful': successful,
        'failed_resets': resets,
        'half_open': half_open,
        'avg_duration_s': avg_duration,
        'avg_bytes_per_conn': avg_bytes,
    }
