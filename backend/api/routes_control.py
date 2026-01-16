"""
Control API Routes

Endpoints for system control and live capture management.
- GET /status - System status and configuration
- POST /capture/start - Start live packet capture
- POST /capture/stop - Stop live packet capture
- GET /capture/status - Live capture status
"""

import json
import os
import subprocess
import sys
import threading
import time
from typing import Dict, Any, Optional
from datetime import datetime
from flask import Blueprint, jsonify, request, current_app

control_bp = Blueprint('control', __name__)

# Global state for live capture
live_capture_process: Optional[subprocess.Popen] = None
live_capture_thread: Optional[threading.Thread] = None
capture_state = {
    'running': False,
    'start_time': None,
    'packets_captured': 0,
    'interface': None,
    'pcap_file': None
}


def get_system_info() -> Dict[str, Any]:
    """Get system and dependency information."""
    info = {
        'python_version': f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        'platform': sys.platform,
        'cwd': os.getcwd(),
        'project_structure': {
            'app': os.path.isdir('app'),
            'scripts': os.path.isdir('scripts'),
            'data': os.path.isdir('data'),
            'logs': os.path.isdir('logs'),
            'api': os.path.isdir('api'),
        }
    }
    
    # Check for tshark
    try:
        result = subprocess.run(['which', 'tshark'], capture_output=True, text=True)
        info['tshark_available'] = result.returncode == 0
    except:
        info['tshark_available'] = False
    
    return info


@control_bp.route('/status', methods=['GET'])
def control_status():
    """
    Get detailed system status.
    
    Returns:
        {
            "api": {...},
            "system": {...},
            "data": {...},
            "capture": {...}
        }
    """
    metrics_dir = current_app.config.get('METRICS_DIR', 'logs')
    baselines_dir = current_app.config.get('BASELINES_DIR', 'app/baselines')
    
    # Check data availability
    data = {
        'metrics': os.path.exists(os.path.join(metrics_dir, 'metrics.jsonl')),
        'anomalies': os.path.exists(os.path.join(metrics_dir, 'anomalies.jsonl')),
        'baselines': all(
            os.path.exists(os.path.join(baselines_dir, f'baseline_{t}.json'))
            for t in ['bandwidth', 'latency', 'protocol', 'connection']
        )
    }
    
    # Count records if they exist
    if data['metrics']:
        try:
            with open(os.path.join(metrics_dir, 'metrics.jsonl')) as f:
                data['metric_count'] = sum(1 for _ in f)
        except:
            data['metric_count'] = 0
    
    if data['anomalies']:
        try:
            with open(os.path.join(metrics_dir, 'anomalies.jsonl')) as f:
                data['anomaly_count'] = sum(1 for _ in f)
        except:
            data['anomaly_count'] = 0
    
    return jsonify({
        'api': {
            'status': 'running',
            'version': '1.0.0',
            'mode': current_app.config.get('MODE'),
            'timestamp': datetime.utcnow().isoformat()
        },
        'system': get_system_info(),
        'data': data,
        'capture': capture_state
    }), 200


@control_bp.route('/ping', methods=['GET'])
def ping():
    """Simple health check."""
    return jsonify({
        'pong': True,
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@control_bp.route('/config', methods=['GET'])
def get_config():
    """
    Get current API configuration.
    
    Returns:
        {
            "mode": "pcap" | "live",
            "pcap_file": str,
            "interface": str,
            "window_size": int,
            "directories": {...}
        }
    """
    return jsonify({
        'mode': current_app.config.get('MODE'),
        'pcap_file': current_app.config.get('PCAP_FILE'),
        'interface': current_app.config.get('INTERFACE'),
        'window_size': current_app.config.get('WINDOW_SIZE'),
        'directories': {
            'metrics': current_app.config.get('METRICS_DIR'),
            'baselines': current_app.config.get('BASELINES_DIR'),
            'anomalies': current_app.config.get('METRICS_DIR')
        }
    }), 200


@control_bp.route('/capture/start', methods=['POST'])
def start_capture():
    """
    Start live packet capture (requires live mode).
    
    Request body (JSON):
        {
            "interface": "eth0",  # required for live mode
            "output_file": "logs/live_capture.jsonl",  # optional
            "duration": 300  # optional, seconds
        }
    
    Returns:
        {
            "success": bool,
            "message": str,
            "interface": str,
            "start_time": str
        }
    """
    global capture_state
    
    data = request.get_json() or {}
    
    # Check if already capturing
    if capture_state['running']:
        return jsonify({
            'success': False,
            'error': 'Capture already running',
            'start_time': capture_state['start_time']
        }), 400
    
    mode = current_app.config.get('MODE')
    
    if mode != 'live':
        return jsonify({
            'success': False,
            'error': f'Cannot start live capture in {mode} mode. Start API with --mode live'
        }), 400
    
    interface = data.get('interface', current_app.config.get('INTERFACE'))
    
    if not interface:
        return jsonify({
            'success': False,
            'error': 'Interface not specified. Provide --interface or in request body'
        }), 400
    
    output_file = data.get('output_file', 'logs/live_capture.jsonl')
    duration = data.get('duration')
    
    try:
        # Build command
        cmd = [
            sys.executable,
            'scripts/live_capture.py',
            interface,
            '--out', output_file
        ]
        
        if duration:
            cmd.extend(['--duration', str(duration)])
        
        # Start process
        live_capture_process = subprocess.Popen(
            cmd,
            cwd=os.getcwd(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Update state
        capture_state['running'] = True
        capture_state['start_time'] = datetime.now().isoformat()
        capture_state['interface'] = interface
        capture_state['pcap_file'] = output_file
        
        return jsonify({
            'success': True,
            'message': f'Live capture started on {interface}',
            'interface': interface,
            'output_file': output_file,
            'start_time': capture_state['start_time'],
            'duration': duration
        }), 200
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@control_bp.route('/capture/stop', methods=['POST'])
def stop_capture():
    """
    Stop live packet capture.
    
    Returns:
        {
            "success": bool,
            "message": str,
            "duration": float,
            "output_file": str
        }
    """
    global capture_state, live_capture_process
    
    if not capture_state['running']:
        return jsonify({
            'success': False,
            'error': 'No capture currently running'
        }), 400
    
    try:
        # Terminate process
        if live_capture_process:
            live_capture_process.terminate()
            live_capture_process.wait(timeout=5)
        
        # Calculate duration
        start = datetime.fromisoformat(capture_state['start_time'])
        duration = (datetime.now() - start).total_seconds()
        
        output_file = capture_state['pcap_file']
        
        # Update state
        capture_state['running'] = False
        
        return jsonify({
            'success': True,
            'message': 'Live capture stopped',
            'duration': round(duration, 2),
            'output_file': output_file
        }), 200
    
    except subprocess.TimeoutExpired:
        if live_capture_process:
            live_capture_process.kill()
        capture_state['running'] = False
        
        return jsonify({
            'success': False,
            'error': 'Process termination timeout'
        }), 500
    
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400


@control_bp.route('/capture/status', methods=['GET'])
def capture_status():
    """
    Get current live capture status.
    
    Returns:
        {
            "running": bool,
            "start_time": str,
            "duration": float,
            "interface": str,
            "output_file": str
        }
    """
    if not capture_state['running']:
        return jsonify({
            'running': False,
            'message': 'No active capture'
        }), 200
    
    start = datetime.fromisoformat(capture_state['start_time'])
    duration = (datetime.now() - start).total_seconds()
    
    return jsonify({
        'running': True,
        'start_time': capture_state['start_time'],
        'duration': round(duration, 2),
        'interface': capture_state['interface'],
        'output_file': capture_state['pcap_file']
    }), 200


@control_bp.route('/logs', methods=['GET'])
def get_logs():
    """
    Get recent log entries.
    
    Query parameters:
        - limit: Number of recent lines to return (default: 100)
        - type: 'app' or 'analysis' (default: app)
    
    Returns:
        {
            "logs": [...]
        }
    """
    log_type = request.args.get('type', default='app')
    limit = request.args.get('limit', default=100, type=int)
    
    log_file = {
        'app': 'logs/app.log',
        'analysis': 'logs/analysis.log'
    }.get(log_type, 'logs/app.log')
    
    if not os.path.exists(log_file):
        return jsonify({
            'logs': [],
            'message': f'Log file not found: {log_file}'
        }), 200
    
    try:
        # Get last N lines
        with open(log_file, 'r') as f:
            lines = f.readlines()
        
        recent = lines[-limit:] if len(lines) > limit else lines
        
        return jsonify({
            'log_file': log_file,
            'limit': limit,
            'total_lines': len(lines),
            'returned_lines': len(recent),
            'logs': recent
        }), 200
    
    except Exception as e:
        return jsonify({
            'error': str(e)
        }), 500
