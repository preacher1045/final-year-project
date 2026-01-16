"""
Anomalies API Routes - ML-based Detection

Endpoints for ML-based anomaly detection using Isolation Forest.
- GET /anomalies - List all detected anomalies
- POST /anomalies/detect - Trigger ML-based anomaly detection
- GET /anomalies/summary - Get summary statistics
"""

import json
import os
from typing import Dict, Any, List
from datetime import datetime
from flask import Blueprint, jsonify, request, current_app
import numpy as np

from app.ml.isolation_forest_model import IsolationForestModel
from app.ml.feature_extractor import FeatureExtractor

anomalies_bp = Blueprint('anomalies', __name__)


def load_metrics_file(filepath: str) -> List[Dict[str, Any]]:
    """Load metrics from JSONL file."""
    metrics = []
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    try:
                        metrics.append(json.loads(line))
                    except:
                        pass
    return metrics


def save_anomalies(anomalies: List[Dict[str, Any]], filepath: str):
    """Save anomalies to JSONL file."""
    os.makedirs(os.path.dirname(filepath) or '.', exist_ok=True)
    with open(filepath, 'w') as f:
        for anomaly in anomalies:
            f.write(json.dumps(anomaly) + '\n')


@anomalies_bp.route('/', methods=['GET'])
def list_anomalies():
    """
    List detected anomalies.
    
    Query parameters:
        - severity: Filter by 'low', 'medium', 'high'
        - is_anomaly: Filter by true/false
        - limit: Max results (default: 100)
        - offset: Skip N results (default: 0)
    """
    try:
        anomalies_file = os.path.join(
            current_app.config.get('ANOMALIES_DIR', 'logs'),
            'anomalies.jsonl'
        )
        
        anomalies = load_metrics_file(anomalies_file)
        
        # Apply filters
        severity = request.args.get('severity')
        is_anomaly_str = request.args.get('is_anomaly')
        limit = int(request.args.get('limit', 100))
        offset = int(request.args.get('offset', 0))
        
        filtered = anomalies
        
        if severity:
            filtered = [a for a in filtered if a.get('severity') == severity]
        
        if is_anomaly_str:
            is_anom = is_anomaly_str.lower() == 'true'
            filtered = [a for a in filtered if a.get('is_anomaly') == is_anom]
        
        total = len(filtered)
        results = filtered[offset:offset + limit]
        
        return jsonify({
            'success': True,
            'count': len(results),
            'total': total,
            'offset': offset,
            'anomalies': results
        }), 200
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@anomalies_bp.route('/detect', methods=['POST'])
def detect_anomalies():
    """
    Run anomaly detection on metrics using trained ML model.
    
    Request body:
        {
            "model_name": str (optional, default="default"),
            "metrics_file": str (optional, default="logs/metrics.jsonl")
        }
    
    Returns:
        {
            "success": bool,
            "anomaly_count": int,
            "anomalies_by_severity": dict,
            "message": str
        }
    """
    try:
        data = request.get_json() or {}
        model_name = data.get('model_name', 'default')
        metrics_file = data.get('metrics_file', 'logs/metrics.jsonl')
        
        # Load metrics
        metrics = load_metrics_file(metrics_file)
        if not metrics:
            return jsonify({'success': False, 'error': 'No metrics found'}), 400
        
        # Load model
        model = IsolationForestModel(
            model_dir=current_app.config.get('MODELS_DIR', 'app/ml/models')
        )
        
        if not model.load(model_name):
            return jsonify({
                'success': False,
                'error': f'Model not found: {model_name}'
            }), 404
        
        # Extract features
        extractor = FeatureExtractor()
        X, valid_indices = extractor.extract_batch(metrics)
        
        if X.shape[0] == 0:
            return jsonify({'success': False, 'error': 'No valid samples'}), 400
        
        # Normalize
        X_norm = extractor.normalize(X, fit=False)
        
        # Predict
        results = model.predict_with_insights(X_norm, valid_indices)
        
        # Save anomalies
        anomalies_file = os.path.join(
            current_app.config.get('ANOMALIES_DIR', 'logs'),
            'anomalies.jsonl'
        )
        save_anomalies(results, anomalies_file)
        
        # Summarize
        summary = {
            'low': sum(1 for r in results if r['severity'] == 'low'),
            'medium': sum(1 for r in results if r['severity'] == 'medium'),
            'high': sum(1 for r in results if r['severity'] == 'high'),
        }
        
        anomaly_count = sum(1 for r in results if r['is_anomaly'])
        
        return jsonify({
            'success': True,
            'anomaly_count': anomaly_count,
            'anomalies_by_severity': summary,
            'total_samples': len(results),
            'anomaly_rate': float(anomaly_count / len(results)) if results else 0,
            'message': 'Anomaly detection completed',
            'timestamp': datetime.utcnow().isoformat(),
        }), 200
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@anomalies_bp.route('/summary', methods=['GET'])
def anomaly_summary():
    """Get summary statistics of detected anomalies."""
    try:
        anomalies_file = os.path.join(
            current_app.config.get('ANOMALIES_DIR', 'logs'),
            'anomalies.jsonl'
        )
        
        anomalies = load_metrics_file(anomalies_file)
        
        if not anomalies:
            return jsonify({
                'success': True,
                'total': 0,
                'by_severity': {'low': 0, 'medium': 0, 'high': 0},
                'anomaly_count': 0,
            }), 200
        
        by_severity = {
            'low': sum(1 for a in anomalies if a.get('severity') == 'low'),
            'medium': sum(1 for a in anomalies if a.get('severity') == 'medium'),
            'high': sum(1 for a in anomalies if a.get('severity') == 'high'),
        }
        
        anomaly_count = sum(1 for a in anomalies if a.get('is_anomaly'))
        
        return jsonify({
            'success': True,
            'total': len(anomalies),
            'anomaly_count': anomaly_count,
            'normal_count': len(anomalies) - anomaly_count,
            'by_severity': by_severity,
            'anomaly_rate': float(anomaly_count / len(anomalies)),
        }), 200
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
