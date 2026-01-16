#!/usr/bin/env python3
"""
Network Traffic Analyzer - REST API Server

A comprehensive Flask API for the network traffic analyzer system.
Supports both PCAP file analysis and live traffic capture.

Features:
- Metrics endpoints (compute, retrieve, stream)
- Anomaly detection endpoints (trigger, view results)
- Baseline management endpoints
- System status and control endpoints
- Support for switching between PCAP and live capture modes
- Structured error handling and response formatting

Usage:
    Development (PCAP testing):
    PYTHONPATH=. python api/api_server.py --mode pcap --pcap data/raw/pcapng/test_net_traffic.pcapng

    Production (Live capture):
    PYTHONPATH=. python api/api_server.py --mode live --interface eth0
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Dict, Any, Tuple
from flask import Flask, jsonify, request
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.main import setup_logging


class APIConfig:
    """Configuration for the API server."""
    DEBUG = False
    TESTING = False
    HOST = '127.0.0.1'
    PORT = 5000
    
    # Storage paths
    METRICS_DIR = 'logs'
    BASELINES_DIR = 'app/baselines'
    ANOMALIES_DIR = 'logs'
    UPLOAD_DIR = 'data/uploads'
    MODELS_DIR = 'app/ml/models'
    
    # Default analysis parameters
    WINDOW_SIZE = 10  # seconds
    MAX_WINDOW_SIZE = 300  # 5 minutes
    RING_BUFFER_SIZE = 100000  # packets
    
    # Mode: 'pcap' or 'live'
    MODE = 'pcap'
    PCAP_FILE = 'data/raw/pcapng/test_net_traffic.pcapng'
    INTERFACE = None
    
    # API response settings
    JSON_SORT_KEYS = True
    JSONIFY_PRETTYPRINT_REGULAR = True


def create_app(config: Dict[str, Any]) -> Flask:
    """
    Create and configure Flask application.
    
    Args:
        config: Configuration dict with keys like MODE, PCAP_FILE, etc.
    
    Returns:
        Configured Flask app
    """
    app = Flask(__name__)
    
    # Update config
    app.config.from_object(APIConfig)
    for key, value in config.items():
        if hasattr(APIConfig, key):
            app.config[key] = value
    
    # Setup logging
    setup_logging()
    
    # Store config for routes to access
    app.analyzer_config = config
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register health check
    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({
            'status': 'ok',
            'timestamp': datetime.utcnow().isoformat(),
            'mode': app.config.get('MODE'),
            'version': '1.0.0'
        }), 200
    
    @app.route('/api/status', methods=['GET'])
    def api_status():
        """Get API and system status."""
        return jsonify({
            'api': {
                'status': 'running',
                'version': '1.0.0',
                'timestamp': datetime.utcnow().isoformat()
            },
            'system': {
                'mode': app.config.get('MODE'),
                'pcap_file': app.config.get('PCAP_FILE') if app.config.get('MODE') == 'pcap' else None,
                'interface': app.config.get('INTERFACE') if app.config.get('MODE') == 'live' else None,
                'window_size': app.config.get('WINDOW_SIZE'),
                'metrics_dir': app.config.get('METRICS_DIR'),
                'baselines_dir': app.config.get('BASELINES_DIR')
            },
            'data': get_data_availability(app.config)
        }), 200
    
    return app


def register_blueprints(app: Flask) -> None:
    """Register all API blueprints."""
    from api.route_anomalies import anomalies_bp
    from api.routes_control import control_bp
    from api.route_upload import upload_bp
    from api.route_training import training_bp
    
    app.register_blueprint(anomalies_bp, url_prefix='/api/anomalies')
    app.register_blueprint(control_bp, url_prefix='/api/control')
    app.register_blueprint(upload_bp, url_prefix='/api')
    app.register_blueprint(training_bp, url_prefix='/api')


def register_error_handlers(app: Flask) -> None:
    """Register error handlers for common exceptions."""
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            'error': 'Bad Request',
            'message': str(error),
            'timestamp': datetime.utcnow().isoformat()
        }), 400
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            'error': 'Not Found',
            'message': 'The requested endpoint does not exist',
            'timestamp': datetime.utcnow().isoformat()
        }), 404
    
    @app.errorhandler(500)
    def server_error(error):
        return jsonify({
            'error': 'Internal Server Error',
            'message': str(error),
            'timestamp': datetime.utcnow().isoformat()
        }), 500
    
    @app.errorhandler(ValueError)
    def value_error(error):
        return jsonify({
            'error': 'Validation Error',
            'message': str(error),
            'timestamp': datetime.utcnow().isoformat()
        }), 400


def get_data_availability(config: Dict[str, Any]) -> Dict[str, Any]:
    """Check what data/baselines are available."""
    metrics_dir = config.get('METRICS_DIR', 'logs')
    baselines_dir = config.get('BASELINES_DIR', 'app/baselines')
    
    availability = {
        'metrics': False,
        'baselines': False,
        'anomalies': False
    }
    
    # Check for metrics file
    metrics_file = os.path.join(metrics_dir, 'metrics.jsonl')
    if os.path.exists(metrics_file):
        availability['metrics'] = True
    
    # Check for baselines
    baseline_files = [
        'baseline_bandwidth.json',
        'baseline_latency.json',
        'baseline_protocols.json',
        'baseline_connections.json'
    ]
    if all(os.path.exists(os.path.join(baselines_dir, f)) for f in baseline_files):
        availability['baselines'] = True
    
    # Check for anomalies file
    anomalies_file = os.path.join(metrics_dir, 'anomalies.jsonl')
    if os.path.exists(anomalies_file):
        availability['anomalies'] = True
    
    return availability


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Network Traffic Analyzer API Server'
    )
    parser.add_argument(
        '--mode',
        choices=['pcap', 'live'],
        default='pcap',
        help='Analysis mode: pcap (file-based) or live (network capture)'
    )
    parser.add_argument(
        '--pcap',
        default='data/raw/pcapng/test_net_traffic.pcapng',
        help='Path to PCAP file (for pcap mode)'
    )
    parser.add_argument(
        '--interface',
        default=None,
        help='Network interface (for live mode)'
    )
    parser.add_argument(
        '--window',
        type=int,
        default=10,
        help='Metric window size in seconds'
    )
    parser.add_argument(
        '--host',
        default='127.0.0.1',
        help='API server host'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=5000,
        help='API server port'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug mode'
    )
    
    args = parser.parse_args()
    
    # Validate PCAP file exists if in pcap mode
    if args.mode == 'pcap':
        if not os.path.exists(args.pcap):
            print(f"Error: PCAP file not found: {args.pcap}")
            sys.exit(1)
    
    # Build config
    config = {
        'MODE': args.mode,
        'PCAP_FILE': args.pcap,
        'INTERFACE': args.interface,
        'WINDOW_SIZE': args.window,
        'DEBUG': args.debug,
        'HOST': args.host,
        'PORT': args.port,
    }
    
    # Create and run app
    app = create_app(config)
    
    print("\n" + "="*70)
    print("Network Traffic Analyzer - REST API Server")
    print("="*70)
    print(f"Mode:      {args.mode}")
    if args.mode == 'pcap':
        print(f"PCAP File: {args.pcap}")
    else:
        print(f"Interface: {args.interface}")
    print(f"Window:    {args.window}s")
    print(f"API:       http://{args.host}:{args.port}")
    print(f"Health:    http://{args.host}:{args.port}/health")
    print(f"Status:    http://{args.host}:{args.port}/api/status")
    print("="*70 + "\n")
    
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    main()
