from collections import Counter
from typing import List, Dict, Any, Tuple


def compute_protocol_distribution(records: List[Dict[str, Any]], key_candidates: Tuple[str, ...] = ('protocol', 'eth_type')) -> Dict[str, Any]:
    """
    Compute protocol distribution from a list of normalized records.

    Args:
        records: list of dicts (canonical records produced by parsers or normalized)
        key_candidates: tuple of keys to check for protocol identification (in order)

    Returns:
        dict with counts, percentages, total, and top_protocols (list of (proto, count, pct)).
    """
    total = 0
    counter = Counter()

    for r in records:
        proto = None
        for k in key_candidates:
            v = r.get(k)
            if v is not None:
                proto = str(v)
                break
        if proto is None:
            # fallback heuristics
            if r.get('src_port') or r.get('dst_port'):
                proto = 'transport'
            else:
                proto = 'unknown'

        counter[proto] += 1
        total += 1

    if total == 0:
        return {'total': 0, 'counts': {}, 'percentages': {}, 'top_protocols': []}

    counts = dict(counter)
    percentages = {p: (c / total) * 100.0 for p, c in counter.items()}
    top_protocols = [(p, c, percentages[p]) for p, c in counter.most_common()]

    return {
        'total': total,
        'counts': counts,
        'percentages': percentages,
        'top_protocols': top_protocols,
    }


def top_n_protocols(distribution: Dict[str, Any], n: int = 10):
    """Return top-n protocols from a distribution object returned by compute_protocol_distribution."""
    return distribution.get('top_protocols', [])[:n]
