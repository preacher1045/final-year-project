"""
Baselines API Routes

Endpoints for baseline profile management.
- GET /baselines - List all baselines
- POST /baselines/generate - Trigger baseline generation
- GET /baselines/:type - Get baseline for specific metric type
"""

import json
import os
import subprocess
import sys
from typing import Dict, Any, List, Tuple
from datetime import datetime
from flask import Blueprint, jsonify, request, current_app

baselines_bp = Blueprint('baselines', __name__)


def load_baseline(baselines_dir: str, baseline_type: str) -> Dict[str, Any]:
    """Load a baseline JSON file."""
    filename = f'baseline_{baseline_type}.json'
    filepath = os.path.join(baselines_dir, filename)
    
    if not os.path.exists(filepath):
        return {}
    
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


def run_baseline_generation(metrics_file: str, baselines_dir: str) -> Tuple[bool, str]:
    """
    Trigger baseline generation from metrics.
    
    Returns:
        (success: bool, message: str)
    """
    if not os.path.exists(metrics_file):
        return False, f"Metrics file not found: {metrics_file}"
    
    try:
        cmd = [
            sys.executable,
            'scripts/generate_baselines.py'
        ]
        
        result = subprocess.run(
            cmd,
            cwd=os.getcwd(),
            capture_output=True,
            text=True,
            timeout=300
        )
        
        if result.returncode != 0:
            return False, f"Generation failed: {result.stderr}"
        
        return True, "Baselines generated successfully"
    
    except subprocess.TimeoutExpired:
        return False, "Baseline generation timed out"
    except Exception as e:
        return False, str(e)


@baselines_bp.route('/', methods=['GET'])
def list_baselines():
    """
    List all available baselines.
    
    Returns:
        {
            "available": int,
            "baselines": {
                "bandwidth": {...},
                "latency": {...},
                "protocol": {...},
                "connection": {...}
            }
        }
    """
    baselines_dir = current_app.config.get('BASELINES_DIR', 'app/baselines')
    
    baseline_types = ['bandwidth', 'latency', 'protocol', 'connection']
    baselines = {}
    
    for btype in baseline_types:
        baseline = load_baseline(baselines_dir, btype)
        if baseline:
            baselines[btype] = baseline
    
    return jsonify({
        'available': len(baselines),
        'baselines': baselines,
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@baselines_bp.route('/<baseline_type>', methods=['GET'])
def get_baseline(baseline_type: str):
    """
    Get a specific baseline by type.
    
    Path parameters:
        - baseline_type: bandwidth, latency, protocol, or connection
    
    Returns:
        The baseline JSON object or 404 if not found
    """
    baselines_dir = current_app.config.get('BASELINES_DIR', 'app/baselines')
    
    baseline = load_baseline(baselines_dir, baseline_type)
    
    if not baseline:
        return jsonify({
            'error': 'Baseline not found',
            'type': baseline_type
        }), 404
    
    return jsonify({
        'type': baseline_type,
        'baseline': baseline,
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@baselines_bp.route('/generate', methods=['POST'])
def generate_baselines():
    """
    Trigger baseline generation from metrics.
    
    Request body (JSON):
        {
            "force": false,  # regenerate even if baselines exist, optional
            "types": ["bandwidth", "latency", "protocol", "connection"]  # optional
        }
    
    Returns:
        {
            "success": bool,
            "message": str,
            "baselines_dir": str,
            "generated": {
                "bandwidth": true,
                "latency": true,
                "protocol": true,
                "connection": true
            },
            "generation_time": float
        }
    """
    from datetime import datetime
    
    start_time = datetime.now()
    
    data = request.get_json() or {}
    force = data.get('force', False)
    requested_types = data.get('types', ['bandwidth', 'latency', 'protocol', 'connection'])
    
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    baselines_dir = current_app.config.get('BASELINES_DIR', 'app/baselines')
    metrics_file = os.path.join(metrics_dir, 'metrics.jsonl')
    
    # Check if metrics exist
    if not os.path.exists(metrics_file):
        return jsonify({
            'success': False,
            'error': 'Metrics not found. Run /api/metrics/compute first.'
        }), 400
    
    # Check if baselines already exist
    baseline_types = ['bandwidth', 'latency', 'protocol', 'connection']
    existing_baselines = {}
    for btype in baseline_types:
        existing_baselines[btype] = bool(load_baseline(baselines_dir, btype))
    
    if all(existing_baselines.values()) and not force:
        return jsonify({
            'success': True,
            'message': 'Baselines already exist',
            'baselines_dir': baselines_dir,
            'generated': existing_baselines,
            'from_cache': True,
            'timestamp': datetime.now().isoformat()
        }), 200
    
    # Run generation
    success, message = run_baseline_generation(metrics_file, baselines_dir)
    
    if not success:
        return jsonify({
            'success': False,
            'error': message
        }), 400
    
    # Check what was generated
    generated = {}
    for btype in baseline_types:
        generated[btype] = bool(load_baseline(baselines_dir, btype))
    
    elapsed = (datetime.now() - start_time).total_seconds()
    
    return jsonify({
        'success': True,
        'message': message,
        'baselines_dir': baselines_dir,
        'generated': generated,
        'generation_time': round(elapsed, 2),
        'timestamp': datetime.now().isoformat()
    }), 200


@baselines_bp.route('/stats', methods=['GET'])
def baseline_stats():
    """
    Get statistics about baselines (min, max, mean values).
    
    Returns:
        {
            "bandwidth": {"mean_bps": float, "max_bps": float, ...},
            "latency": {"mean_rtt": float, "p95_rtt": float, ...},
            ...
        }
    """
    baselines_dir = current_app.config.get('BASELINES_DIR', 'app/baselines')
    
    baseline_types = ['bandwidth', 'latency', 'protocol', 'connection']
    stats = {}
    
    for btype in baseline_types:
        baseline = load_baseline(baselines_dir, btype)
        if baseline:
            # Extract key stats from baseline
            stats[btype] = {}
            
            if btype == 'bandwidth':
                if 'mean' in baseline:
                    stats[btype]['mean_bps'] = baseline['mean']
                if 'median' in baseline:
                    stats[btype]['median_bps'] = baseline['median']
                if 'max' in baseline:
                    stats[btype]['max_bps'] = baseline['max']
                if 'min' in baseline:
                    stats[btype]['min_bps'] = baseline['min']
                if 'p95' in baseline:
                    stats[btype]['p95_bps'] = baseline['p95']
            
            elif btype == 'latency':
                if 'mean' in baseline:
                    stats[btype]['mean_rtt'] = baseline['mean']
                if 'median' in baseline:
                    stats[btype]['median_rtt'] = baseline['median']
                if 'p95' in baseline:
                    stats[btype]['p95_rtt'] = baseline['p95']
                if 'p99' in baseline:
                    stats[btype]['p99_rtt'] = baseline['p99']
            
            elif btype == 'protocol':
                if 'distribution' in baseline:
                    stats[btype]['distribution'] = baseline['distribution']
            
            elif btype == 'connection':
                if 'mean' in baseline:
                    stats[btype]['mean_connections'] = baseline['mean']
                if 'median' in baseline:
                    stats[btype]['median_connections'] = baseline['median']
    
    return jsonify({
        'baseline_stats': stats,
        'timestamp': datetime.utcnow().isoformat()
    }), 200
