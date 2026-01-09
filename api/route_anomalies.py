"""
Anomalies API Routes

Endpoints for anomaly detection results and triggering detection.
- GET /anomalies - List all detected anomalies
- POST /anomalies/detect - Trigger anomaly detection
- GET /anomalies/:window_id - Get anomalies for specific window
"""

import json
import os
import subprocess
import sys
from typing import Dict, Any, List, Tuple
from datetime import datetime
from flask import Blueprint, jsonify, request, current_app

anomalies_bp = Blueprint('anomalies', __name__)


def load_anomalies_file(filepath: str) -> List[Dict[str, Any]]:
    """Load anomalies from JSONL file."""
    anomalies = []
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        anomalies.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return anomalies


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


def run_anomaly_detection(metrics_file: str, output_file: str) -> Tuple[bool, str]:
    """
    Trigger anomaly detection on metrics.
    
    Returns:
        (success: bool, message: str)
    """
    if not os.path.exists(metrics_file):
        return False, f"Metrics file not found: {metrics_file}"
    
    try:
        cmd = [
            sys.executable,
            '-m', 'app.anomalies.anomaly_engine',
            '--metrics', metrics_file,
            '--out', output_file
        ]
        
        result = subprocess.run(
            cmd,
            cwd=os.getcwd(),
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            return False, f"Detection failed: {result.stderr}"
        
        return True, "Anomaly detection completed"
    
    except subprocess.TimeoutExpired:
        return False, "Anomaly detection timed out"
    except Exception as e:
        return False, str(e)


@anomalies_bp.route('/', methods=['GET'])
def list_anomalies():
    """
    List all detected anomalies.
    
    Query parameters:
        - type: Filter by type (traffic_spike, port_scan, high_latency, etc.)
        - severity: Filter by severity (medium, high)
        - limit: Max number to return (default: 100)
        - offset: Skip N anomalies (default: 0)
    
    Returns:
        {
            "count": int,
            "total": int,
            "anomalies": [
                {
                    "type": str,
                    "severity": str,
                    "window_start": float,
                    "window_end": float,
                    "message": str,
                    ...
                }
            ]
        }
    """
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    anomalies_file = os.path.join(metrics_dir, 'anomalies.jsonl')
    
    filter_type = request.args.get('type')
    filter_severity = request.args.get('severity')
    limit = request.args.get('limit', default=100, type=int)
    offset = request.args.get('offset', default=0, type=int)
    
    all_anomalies = load_anomalies_file(anomalies_file)
    
    # Apply filters
    filtered = all_anomalies
    if filter_type:
        filtered = [a for a in filtered if a.get('type') == filter_type]
    if filter_severity:
        filtered = [a for a in filtered if a.get('severity') == filter_severity]
    
    # Paginate
    paginated = filtered[offset:offset + limit]
    
    if not all_anomalies:
        return jsonify({
            'count': 0,
            'total': 0,
            'anomalies': [],
            'message': 'No anomalies found. Run /api/anomalies/detect first.'
        }), 200
    
    return jsonify({
        'count': len(paginated),
        'total': len(filtered),
        'offset': offset,
        'limit': limit,
        'filters': {
            'type': filter_type,
            'severity': filter_severity
        },
        'anomalies': paginated
    }), 200


@anomalies_bp.route('/by-type', methods=['GET'])
def anomalies_by_type():
    """
    Get anomalies grouped by type with counts.
    
    Returns:
        {
            "total": int,
            "by_type": {
                "traffic_spike": {"count": int, "severity_breakdown": {...}},
                "port_scan": {...},
                ...
            }
        }
    """
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    anomalies_file = os.path.join(metrics_dir, 'anomalies.jsonl')
    
    all_anomalies = load_anomalies_file(anomalies_file)
    
    by_type = {}
    for anomaly in all_anomalies:
        atype = anomaly.get('type', 'unknown')
        severity = anomaly.get('severity', 'unknown')
        
        if atype not in by_type:
            by_type[atype] = {'count': 0, 'by_severity': {}}
        
        by_type[atype]['count'] += 1
        
        if severity not in by_type[atype]['by_severity']:
            by_type[atype]['by_severity'][severity] = 0
        by_type[atype]['by_severity'][severity] += 1
    
    return jsonify({
        'total': len(all_anomalies),
        'by_type': by_type
    }), 200


@anomalies_bp.route('/window/<int:window_id>', methods=['GET'])
def get_window_anomalies(window_id: int):
    """
    Get anomalies for a specific metric window.
    
    Returns:
        {
            "window_id": int,
            "anomalies": [...],
            "count": int
        }
    """
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    anomalies_file = os.path.join(metrics_dir, 'anomalies.jsonl')
    
    all_anomalies = load_anomalies_file(anomalies_file)
    
    window_anomalies = [
        a for a in all_anomalies
        if a.get('window_id') == window_id
    ]
    
    return jsonify({
        'window_id': window_id,
        'count': len(window_anomalies),
        'anomalies': window_anomalies
    }), 200


@anomalies_bp.route('/detect', methods=['POST'])
def detect_anomalies():
    """
    Trigger anomaly detection on metrics.
    
    Request body (JSON):
        {
            "force": false,  # recompute even if anomalies exist, optional
            "window_start": float,  # optional, filter to windows >= this
            "window_end": float    # optional, filter to windows <= this
        }
    
    Returns:
        {
            "success": bool,
            "message": str,
            "anomalies_file": str,
            "anomaly_count": int,
            "detection_time": float,
            "summary": {
                "by_type": {...},
                "by_severity": {...}
            }
        }
    """
    from datetime import datetime
    
    start_time = datetime.now()
    
    data = request.get_json() or {}
    force = data.get('force', False)
    
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    metrics_file = os.path.join(metrics_dir, 'metrics.jsonl')
    anomalies_file = os.path.join(metrics_dir, 'anomalies.jsonl')
    
    # Check if metrics exist
    if not os.path.exists(metrics_file):
        return jsonify({
            'success': False,
            'error': 'Metrics not found. Run /api/metrics/compute first.'
        }), 400
    
    # Check if anomalies already exist
    if os.path.exists(anomalies_file) and not force:
        existing = load_anomalies_file(anomalies_file)
        
        # Compute summary
        by_type = {}
        by_severity = {}
        for anom in existing:
            atype = anom.get('type', 'unknown')
            severity = anom.get('severity', 'unknown')
            
            by_type[atype] = by_type.get(atype, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        return jsonify({
            'success': True,
            'message': 'Anomalies already detected',
            'anomalies_file': anomalies_file,
            'anomaly_count': len(existing),
            'from_cache': True,
            'summary': {
                'by_type': by_type,
                'by_severity': by_severity
            },
            'timestamp': datetime.now().isoformat()
        }), 200
    
    # Run detection
    success, message = run_anomaly_detection(metrics_file, anomalies_file)
    
    if not success:
        return jsonify({
            'success': False,
            'error': message
        }), 400
    
    # Load and summarize results
    anomalies = load_anomalies_file(anomalies_file)
    
    by_type = {}
    by_severity = {}
    for anom in anomalies:
        atype = anom.get('type', 'unknown')
        severity = anom.get('severity', 'unknown')
        
        by_type[atype] = by_type.get(atype, 0) + 1
        by_severity[severity] = by_severity.get(severity, 0) + 1
    
    elapsed = (datetime.now() - start_time).total_seconds()
    
    return jsonify({
        'success': True,
        'message': message,
        'anomalies_file': anomalies_file,
        'anomaly_count': len(anomalies),
        'detection_time': round(elapsed, 2),
        'summary': {
            'by_type': by_type,
            'by_severity': by_severity
        },
        'timestamp': datetime.now().isoformat()
    }), 200


@anomalies_bp.route('/top', methods=['GET'])
def top_anomalies():
    """
    Get top N anomalies by recent occurrence.
    
    Query parameters:
        - limit: Number of top anomalies to return (default: 10)
    
    Returns:
        {
            "top": [
                {
                    "type": str,
                    "severity": str,
                    "message": str,
                    "count": int,
                    "first_seen": float,
                    "last_seen": float
                }
            ]
        }
    """
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    anomalies_file = os.path.join(metrics_dir, 'anomalies.jsonl')
    limit = request.args.get('limit', default=10, type=int)
    
    all_anomalies = load_anomalies_file(anomalies_file)
    
    # Group by message and aggregate
    grouped = {}
    for anom in all_anomalies:
        msg = anom.get('message', 'unknown')
        if msg not in grouped:
            grouped[msg] = {
                'type': anom.get('type'),
                'severity': anom.get('severity'),
                'message': msg,
                'count': 0,
                'first_seen': anom.get('window_start'),
                'last_seen': anom.get('window_start')
            }
        grouped[msg]['count'] += 1
        grouped[msg]['last_seen'] = max(
            grouped[msg]['last_seen'],
            anom.get('window_start', 0)
        )
    
    # Sort by count descending
    top = sorted(grouped.values(), key=lambda x: x['count'], reverse=True)[:limit]
    
    return jsonify({
        'top': top
    }), 200
