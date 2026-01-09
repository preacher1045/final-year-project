"""
Metrics API Routes

Endpoints for retrieving and computing network traffic metrics.
- GET /metrics - List all computed metrics
- POST /metrics/compute - Trigger metrics computation
- GET /metrics/:window_id - Get metrics for specific window
"""

import json
import os
import subprocess
import sys
from typing import Dict, Any, List, Tuple
from datetime import datetime
from flask import Blueprint, jsonify, request, current_app

metrics_bp = Blueprint('metrics', __name__)


def load_metrics_file(filepath: str) -> List[Dict[str, Any]]:
    """Load metrics from JSONL file."""
    metrics = []
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        metrics.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return metrics


def compute_metrics_from_pcap(pcap_path: str, window_size: int, output_file: str) -> Tuple[bool, str]:
    """
    Trigger metrics computation from PCAP file.
    
    Returns:
        (success: bool, message: str)
    """
    if not os.path.exists(pcap_path):
        return False, f"PCAP file not found: {pcap_path}"
    
    try:
        # Build command
        cmd = [
            sys.executable,
            'scripts/run_metrics.py',
            '--pcap', pcap_path,
            '--window', str(window_size),
            '--out', output_file
        ]
        
        # Run metrics computation
        result = subprocess.run(
            cmd,
            cwd=os.getcwd(),
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            return False, f"Metrics computation failed: {result.stderr}"
        
        return True, "Metrics computed successfully"
    
    except subprocess.TimeoutExpired:
        return False, "Metrics computation timed out"
    except Exception as e:
        return False, str(e)


@metrics_bp.route('/', methods=['GET'])
def list_metrics():
    """
    List all computed metrics.
    
    Query parameters:
        - limit: Max number of windows to return (default: 50)
        - offset: Skip N windows (default: 0)
    
    Returns:
        {
            "count": int,
            "total": int,
            "metrics": [
                {
                    "window_start": float,
                    "window_end": float,
                    "bandwidth": {...},
                    "latency": {...},
                    "connections": {...},
                    "protocol": {...},
                    ...
                }
            ]
        }
    """
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    metrics_file = os.path.join(metrics_dir, 'metrics.jsonl')
    
    limit = request.args.get('limit', default=50, type=int)
    offset = request.args.get('offset', default=0, type=int)
    
    # Load metrics
    all_metrics = load_metrics_file(metrics_file)
    
    if not all_metrics:
        return jsonify({
            'count': 0,
            'total': 0,
            'metrics': [],
            'message': 'No metrics found. Run /api/metrics/compute first.'
        }), 200
    
    # Paginate
    paginated = all_metrics[offset:offset + limit]
    
    return jsonify({
        'count': len(paginated),
        'total': len(all_metrics),
        'offset': offset,
        'limit': limit,
        'metrics': paginated
    }), 200


@metrics_bp.route('/<int:window_id>', methods=['GET'])
def get_metric_window(window_id: int):
    """
    Get metrics for a specific window (0-indexed).
    
    Returns:
        {
            "window_id": int,
            "window_start": float,
            "window_end": float,
            "bandwidth": {...},
            "latency": {...},
            "connections": {...},
            "protocol": {...},
            ...
        }
    """
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    metrics_file = os.path.join(metrics_dir, 'metrics.jsonl')
    
    all_metrics = load_metrics_file(metrics_file)
    
    if window_id < 0 or window_id >= len(all_metrics):
        return jsonify({
            'error': 'Window not found',
            'window_id': window_id,
            'total_windows': len(all_metrics)
        }), 404
    
    metric = all_metrics[window_id].copy()
    metric['window_id'] = window_id
    
    return jsonify(metric), 200


@metrics_bp.route('/compute', methods=['POST'])
def compute_metrics():
    """
    Trigger metrics computation from PCAP or live capture.
    
    Request body (JSON):
        {
            "source": "pcap" | "live",  # optional, uses config default
            "pcap_file": "path/to/file.pcapng",  # if source=pcap
            "window_size": 10,  # seconds, optional
            "force": false  # recompute even if metrics exist, optional
        }
    
    Returns:
        {
            "success": bool,
            "message": str,
            "metrics_file": str,
            "window_count": int,
            "computation_time": float
        }
    """
    from datetime import datetime
    
    start_time = datetime.now()
    
    data = request.get_json() or {}
    source = data.get('source', current_app.config.get('MODE'))
    window_size = data.get('window_size', current_app.config.get('WINDOW_SIZE', 10))
    force = data.get('force', False)
    
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    os.makedirs(metrics_dir, exist_ok=True)
    
    metrics_file = os.path.join(metrics_dir, 'metrics.jsonl')
    
    # Check if metrics already exist
    if os.path.exists(metrics_file) and not force:
        existing = load_metrics_file(metrics_file)
        return jsonify({
            'success': True,
            'message': 'Metrics already computed',
            'metrics_file': metrics_file,
            'window_count': len(existing),
            'timestamp': datetime.now().isoformat()
        }), 200
    
    if source == 'pcap':
        pcap_file = data.get('pcap_file', current_app.config.get('PCAP_FILE'))
        
        success, message = compute_metrics_from_pcap(pcap_file, window_size, metrics_file)
        
        if not success:
            return jsonify({
                'success': False,
                'error': message
            }), 400
        
        # Count windows
        metrics = load_metrics_file(metrics_file)
        
        elapsed = (datetime.now() - start_time).total_seconds()
        
        return jsonify({
            'success': True,
            'message': message,
            'metrics_file': metrics_file,
            'window_count': len(metrics),
            'window_size': window_size,
            'computation_time': round(elapsed, 2),
            'timestamp': datetime.now().isoformat()
        }), 200
    
    elif source == 'live':
        return jsonify({
            'success': False,
            'error': 'Live metrics not yet implemented. Use /api/control/capture endpoints.'
        }), 400
    
    else:
        return jsonify({
            'success': False,
            'error': f'Unknown source: {source}'
        }), 400


@metrics_bp.route('/summary', methods=['GET'])
def metrics_summary():
    """
    Get summary statistics across all metrics.
    
    Returns:
        {
            "total_windows": int,
            "time_span": float (seconds),
            "bandwidth": {"mean": float, "max": float, "min": float},
            "latency": {"mean": float, "max": float, "p95": float},
            "connections": {"total": int, "per_window": float},
            "protocols": {...}
        }
    """
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    metrics_file = os.path.join(metrics_dir, 'metrics.jsonl')
    
    all_metrics = load_metrics_file(metrics_file)
    
    if not all_metrics:
        return jsonify({
            'error': 'No metrics found'
        }), 404
    
    # Compute aggregates
    bps_values = []
    rtt_values = []
    conn_counts = []
    
    for m in all_metrics:
        if 'bandwidth' in m and 'mean_bps' in m['bandwidth']:
            bps_values.append(m['bandwidth']['mean_bps'])
        if 'latency' in m and 'mean_rtt' in m['latency']:
            rtt_values.append(m['latency']['mean_rtt'])
        if 'connections' in m and 'total' in m['connections']:
            conn_counts.append(m['connections']['total'])
    
    summary = {
        'total_windows': len(all_metrics),
        'time_span': all_metrics[-1].get('window_end', 0) - all_metrics[0].get('window_start', 0),
        'bandwidth': {
            'mean_bps': round(sum(bps_values) / len(bps_values), 2) if bps_values else 0,
            'max_bps': round(max(bps_values), 2) if bps_values else 0,
            'min_bps': round(min(bps_values), 2) if bps_values else 0,
        },
        'latency': {
            'mean_rtt': round(sum(rtt_values) / len(rtt_values), 2) if rtt_values else 0,
            'max_rtt': round(max(rtt_values), 2) if rtt_values else 0,
        },
        'connections': {
            'total_across_windows': sum(conn_counts),
            'mean_per_window': round(sum(conn_counts) / len(conn_counts), 2) if conn_counts else 0,
        }
    }
    
    return jsonify(summary), 200
