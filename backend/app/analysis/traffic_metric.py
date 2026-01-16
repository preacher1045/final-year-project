from collections import Counter, defaultdict
from typing import List, Dict, Any
import math
import statistics


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


def compute_metrics(window_records: List[Dict[str, Any]]) -> Dict[str, Any]:
	"""
	Compute traffic metrics from parsed packet/frame records within a time window.

	Each record is expected to be a dict produced by parsers, e.g. keys like:
	  - 'timestamp' (ISO string) or numeric
	  - 'src_ip', 'dst_ip'
	  - 'src_port', 'dst_port'
	  - 'eth_type', 'protocol' or parsed equivalents
	  - 'length' or payload/packet size
	  - TCP-specific: 'flags', 'seq', 'ack'

	Returns a dictionary with aggregated metrics.
	"""
	metrics = {}

	total_packets = len(window_records)
	total_bytes = 0

	pkt_sizes = []
	proto_counter = Counter()
	src_counter = Counter()
	dst_counter = Counter()
	src_port_counter = Counter()
	dst_port_counter = Counter()
	tcp_flags = Counter()

	# Simple flow key: 5-tuple sorted for directionless flows
	flows = defaultdict(lambda: {"packets": 0, "bytes": 0, "first_ts": None, "last_ts": None})

	for rec in window_records:
		# sizes
		size = None
		if rec.get('length') is not None:
			try:
				size = int(rec.get('length'))
			except Exception:
				size = None
		# fallback: no size provided
		if size is None:
			# If parsers included raw payload length under 'payload_len' or 'packet_len'
			for k in ('payload_len', 'packet_len'):
				if k in rec:
					try:
						size = int(rec[k])
						break
					except Exception:
						pass
		if size is None:
			# approximate as 0
			size = 0
		total_bytes += size
		pkt_sizes.append(size)

		# protocols
		proto = None
		if 'protocol' in rec and rec['protocol'] is not None:
			proto = str(rec['protocol'])
		elif 'eth_type' in rec and rec['eth_type'] is not None:
			proto = str(rec['eth_type'])
		elif 'src_port' in rec or 'dst_port' in rec:
			proto = 'transport'
		else:
			proto = 'unknown'
		proto_counter[proto] += 1

		# endpoints
		if 'src_ip' in rec and rec['src_ip']:
			src_counter[rec['src_ip']] += 1
		if 'dst_ip' in rec and rec['dst_ip']:
			dst_counter[rec['dst_ip']] += 1

		# ports
		if 'src_port' in rec and rec['src_port']:
			src_port_counter[str(rec['src_port'])] += 1
		if 'dst_port' in rec and rec['dst_port']:
			dst_port_counter[str(rec['dst_port'])] += 1

		# TCP flags
		if 'flags' in rec and rec['flags']:
			tcp_flags[str(rec['flags'])] += 1

		# flows
		src = rec.get('src_ip')
		dst = rec.get('dst_ip')
		sport = rec.get('src_port')
		dport = rec.get('dst_port')
		proto_short = rec.get('protocol') or rec.get('eth_type') or 'ip'
		if src and dst:
			# directionless flow key tuple
			key = (src, dst, sport, dport, str(proto_short))
			f = flows[key]
			f['packets'] += 1
			f['bytes'] += size
			# timestamps if present
			ts = rec.get('timestamp')
			if ts is not None:
				if f['first_ts'] is None:
					f['first_ts'] = ts
				f['last_ts'] = ts

	# High-level metrics
	metrics['total_packets'] = total_packets
	metrics['total_bytes'] = total_bytes
	metrics['packet_rate_pps'] = None
	metrics['byte_rate_bps'] = None

	# Size distribution
	metrics['pkt_size'] = {
		'min': min(pkt_sizes) if pkt_sizes else None,
		'max': max(pkt_sizes) if pkt_sizes else None,
		'mean': statistics.mean(pkt_sizes) if pkt_sizes else None,
		'median': statistics.median(pkt_sizes) if pkt_sizes else None,
		'percentiles': _percentiles(pkt_sizes, (50, 90, 99)),
	}

	# Top talkers
	metrics['top_src_ips'] = src_counter.most_common(10)
	metrics['top_dst_ips'] = dst_counter.most_common(10)
	metrics['top_src_ports'] = src_port_counter.most_common(10)
	metrics['top_dst_ports'] = dst_port_counter.most_common(10)

	# Protocol distribution
	metrics['protocol_distribution'] = dict(proto_counter)

	# TCP flags
	metrics['tcp_flags'] = dict(tcp_flags)

	# Flow stats: counts and basic aggregates
	flow_stats = [
		{'packets': v['packets'], 'bytes': v['bytes'], 'duration': None if not v['first_ts'] or not v['last_ts'] else 0}
		for v in flows.values()
	]
	# compute simple duration if timestamps are numeric (best-effort)
	durations = []
	for v in flows.values():
		if v['first_ts'] and v['last_ts']:
			try:
				durations.append(float(v['last_ts']) - float(v['first_ts']))
			except Exception:
				pass

	metrics['flow_count'] = len(flows)
	metrics['flow_packets_mean'] = statistics.mean([f['packets'] for f in flow_stats]) if flow_stats else None
	metrics['flow_bytes_mean'] = statistics.mean([f['bytes'] for f in flow_stats]) if flow_stats else None
	metrics['flow_duration_mean'] = statistics.mean(durations) if durations else None

	return metrics


def normalize_record(rec: Dict[str, Any]) -> Dict[str, Any]:
	"""
	Map various parser outputs into the canonical record schema expected by compute_metrics.

	Canonical keys produced: timestamp, src_ip, dst_ip, src_port, dst_port, length,
	protocol, flags, seq, ack, plus any original fields preserved.
	"""
	out = dict(rec)  # start with a shallow copy

	# timestamp: if ISO string, leave; conversion to numeric happens in runner if needed
	ts = rec.get('timestamp')
	out['timestamp'] = ts

	# IPs
	for k in ('src_ip', 'source_ip', 'src'):
		if out.get('src_ip'):
			break
		if k in rec and rec[k]:
			out['src_ip'] = rec[k]
	for k in ('dst_ip', 'dest_ip', 'dst'):
		if out.get('dst_ip'):
			break
		if k in rec and rec[k]:
			out['dst_ip'] = rec[k]

	# ports
	if not out.get('src_port'):
		for k in ('src_port', 'sport', 'source_port'):
			if k in rec and rec[k] is not None:
				out['src_port'] = rec[k]
				break
	if not out.get('dst_port'):
		for k in ('dst_port', 'dport', 'dest_port'):
			if k in rec and rec[k] is not None:
				out['dst_port'] = rec[k]
				break

	# length
	if out.get('length') is None:
		for k in ('length', 'packet_len', 'payload_len'):
			if k in rec and rec[k] is not None:
				try:
					out['length'] = int(rec[k])
					break
				except Exception:
					pass
	if out.get('length') is None:
		out['length'] = 0

	# protocol
	if out.get('protocol') is None:
		if 'protocol' in rec and rec['protocol'] is not None:
			out['protocol'] = rec['protocol']
		elif 'eth_type' in rec and rec['eth_type'] is not None:
			out['protocol'] = rec['eth_type']
		else:
			out['protocol'] = None

	# tcp flags/seq/ack
	out['flags'] = out.get('flags') or out.get('tcp_flags') or None
	out['seq'] = out.get('seq') or out.get('tcp_seq') or None
	out['ack'] = out.get('ack') or out.get('tcp_ack') or None

	return out


def deduplicate_records(records: List[Dict[str, Any]], tolerance_ms: int = 1) -> List[Dict[str, Any]]:
	"""
	Deduplicate records using a robust signature.

	Strategy:
	  - If a frame number exists (`frame_number`, `frame_no`, `frame_idx`), use it as a unique id.
	  - Otherwise, round timestamps to `tolerance_ms` milliseconds and build a signature of
		(rounded_ts, src_ip, dst_ip, src_port, dst_port, length, protocol).

	Keeps the first occurrence of each signature and returns the filtered list preserving order.
	"""
	seen = set()
	out = []

	def _get_frame_num(r):
		for k in ('frame_number', 'frame_no', 'frame_idx', 'frame_num'):
			if k in r and r[k] is not None:
				try:
					return int(r[k])
				except Exception:
					return str(r[k])
		return None

	for r in records:
		# prefer explicit frame number if present
		fn = _get_frame_num(r)
		if fn is not None:
			sig = ('frame', fn)
		else:
			# round timestamp
			ts = r.get('timestamp')
			try:
				# try numeric
				tval = float(ts) if ts is not None else None
			except Exception:
				# try ISO parse fallback: use original string as last resort
				tval = None
			if tval is not None:
				# round to tolerance_ms
				rounded = int(round(tval * 1000.0 / max(1, tolerance_ms)))
			else:
				rounded = str(ts)

			sig = (
				rounded,
				str(r.get('src_ip') or ''),
				str(r.get('dst_ip') or ''),
				str(r.get('src_port') or ''),
				str(r.get('dst_port') or ''),
				str(r.get('length') or ''),
				str(r.get('protocol') or r.get('eth_type') or ''),
			)

		if sig in seen:
			continue
		seen.add(sig)
		out.append(r)
	return out

