"""Model Training and Management Routes"""

import json
import os
import subprocess
import sys
from typing import Dict, Any, Generator, Tuple
from datetime import datetime
from flask import Blueprint, request, jsonify, current_app
import numpy as np

from app.ml.isolation_forest_model import IsolationForestModel
from app.ml.feature_extractor import FeatureExtractor

training_bp = Blueprint('training', __name__)

def load_metrics_jsonl(filepath: str):
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

def stream_metrics_jsonl(filepath: str, batch_size: int = 100) -> Generator[Dict[str, Any], None, None]:
    """
    Stream metrics from JSONL file in batches to avoid loading entire file into memory.
    
    Args:
        filepath: Path to metrics JSONL file
        batch_size: Number of lines to read per batch
    
    Yields:
        Batch of metric dictionaries
    """
    if not os.path.exists(filepath):
        return
    
    batch = []
    with open(filepath, 'r') as f:
        for line in f:
            if line.strip():
                try:
                    batch.append(json.loads(line))
                    if len(batch) >= batch_size:
                        yield batch
                        batch = []
                except:
                    pass
        
        if batch:
            yield batch

def get_dataset_stats(metrics: list) -> Dict[str, Any]:
    """
    Analyze dataset characteristics to recommend optimal sampling.
    
    Returns:
        {
            'total_windows': int,
            'time_span_seconds': float,
            'temporal_variance': float (0-1),
            'recommended_strategy': str,
            'training_samples_needed': int,
            'estimated_training_time_seconds': float
        }
    """
    if not metrics:
        return {
            'total_windows': 0,
            'recommendation': 'no_data',
            'training_samples_needed': 0
        }
    
    total_windows = len(metrics)
    
    # Extract bandwidth data to measure variance
    bps_values = []
    for m in metrics:
        bps = m.get('bandwidth', {}).get('avg_bps', 0)
        if bps > 0:
            bps_values.append(bps)
    
    if bps_values:
        mean_bps = np.mean(bps_values)
        std_bps = np.std(bps_values)
        cv = std_bps / mean_bps if mean_bps > 0 else 0  # Coefficient of variation
    else:
        cv = 0
    
    # Recommendations based on dataset size and variance
    if total_windows <= 50:
        strategy = 'use_all'
        training_samples = total_windows
        est_time = 0.5
    elif total_windows <= 500:
        strategy = 'use_all' if cv > 0.5 else 'sample_0.8'
        training_samples = total_windows
        est_time = 1.0
    elif total_windows <= 5000:
        strategy = 'stratified_0.8' if cv > 0.5 else 'systematic_0.5'
        training_samples = min(5000, total_windows)
        est_time = 2.0
    else:
        strategy = 'stratified_0.25' if cv > 0.5 else 'systematic_0.1'
        training_samples = max(500, int(total_windows * 0.25))
        est_time = 5.0
    
    return {
        'total_windows': total_windows,
        'coefficient_of_variation': round(cv, 3),
        'variance_type': 'high' if cv > 0.5 else 'moderate' if cv > 0.2 else 'low',
        'recommended_strategy': strategy,
        'training_samples_needed': training_samples,
        'estimated_training_time_seconds': est_time,
        'note': 'High variance detected; stratified sampling recommended' if cv > 0.5 else 'Data is relatively uniform; systematic sampling acceptable'
    }

@training_bp.route('/train', methods=['POST'])
def train_model():
    """
    Train a new Isolation Forest model on uploaded PCAP file.
    
    Request body:
        {
            "file_id": str,
            "model_name": str (optional, default="default"),
            "contamination": float (optional, default=0.1),
            "use_existing_metrics": bool (optional),
            "sample_rate": float (optional, 0.0-1.0, None=auto-select),
            "sampling_strategy": str (optional, 'uniform'/'stratified'/'systematic', default='uniform')
        }
    
    Returns:
        {
            "success": bool,
            "model_name": str,
            "training_samples": int,
            "training_samples_before_sampling": int,
            "sampling_strategy": str,
            "sample_rate_actual": float,
            "reduction_percent": float,
            "anomalies_detected": int,
            "anomaly_rate": float,
            "timestamp": str,
            "recommendation": dict (if auto-selected)
        }
    """
    try:
        data = request.get_json() or {}
        file_id = data.get('file_id')
        model_name = data.get('model_name', 'default')
        contamination = float(data.get('contamination', 0.1))
        use_existing = data.get('use_existing_metrics', False)
        sample_rate = data.get('sample_rate')
        sampling_strategy = data.get('sampling_strategy', 'uniform')
        
        if not file_id:
            return jsonify({'success': False, 'error': 'file_id required'}), 400
        
        # Load or compute metrics
        metrics_file = os.path.join(current_app.config.get('METRICS_DIR', 'logs'), 'metrics.jsonl')
        
        if use_existing and os.path.exists(metrics_file):
            metrics = load_metrics_jsonl(metrics_file)
        else:
            # Find PCAP file
            upload_dir = current_app.config.get('UPLOAD_DIR', 'data/uploads')
            pcap_path = None
            for f in os.listdir(upload_dir):
                if file_id in f:
                    pcap_path = os.path.join(upload_dir, f)
                    break
            
            if not pcap_path or not os.path.exists(pcap_path):
                return jsonify({'success': False, 'error': 'PCAP file not found'}), 404
            
            # Compute metrics using subprocess
            cmd = [
                sys.executable,
                'scripts/run_metrics.py',
                '--pcap', pcap_path,
                '--out', metrics_file
            ]
            
            result = subprocess.run(
                cmd,
                cwd=os.getcwd(),
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                return jsonify({
                    'success': False,
                    'error': f'Metrics computation failed: {result.stderr}'
                }), 500
            
            metrics = load_metrics_jsonl(metrics_file)
        
        if len(metrics) < 10:
            return jsonify({
                'success': False,
                'error': f'Need at least 10 metric windows, got {len(metrics)}'
            }), 400
        
        # Extract features
        extractor = FeatureExtractor()
        X, valid_indices, sampling_stats = extractor.extract_batch(
            metrics,
            sample_rate=sample_rate,
            sampling_strategy=sampling_strategy
        )
        
        if X.shape[0] < 10:
            return jsonify({
                'success': False,
                'error': f'Not enough valid samples after feature extraction: {X.shape[0]}'
            }), 400
        
        # Auto-select sample rate if not specified
        recommendation = None
        if sample_rate is None:
            recommendation = FeatureExtractor.recommend_sample_rate(X.shape[0])
            auto_rate = recommendation.get('suggested_rate')
            
            # Re-sample if recommendation differs from current
            if auto_rate != 1.0:
                X, valid_indices, sampling_stats = extractor.extract_batch(
                    metrics,
                    sample_rate=auto_rate,
                    sampling_strategy=sampling_strategy
                )
        
        # Normalize
        X_norm = extractor.normalize(X, fit=True)
        
        # Train model
        model = IsolationForestModel(
            contamination=contamination,
            model_dir=current_app.config.get('MODELS_DIR', 'app/ml/models')
        )
        
        result = model.train(X_norm, extractor.get_feature_names(), model_name)
        
        # Enhance result with sampling information
        result.update({
            'training_samples_before_sampling': sampling_stats['valid_samples_found'],
            'sampling_strategy': sampling_stats['strategy'],
            'sample_rate_actual': sampling_stats['sample_rate_actual'],
            'reduction_percent': sampling_stats['reduction_percent']
        })
        
        if recommendation:
            result['auto_recommendation'] = recommendation
        
        return jsonify(result), 200
    
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Metrics computation timed out'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@training_bp.route('/analyze', methods=['POST'])
def analyze_dataset():
    """
    Analyze dataset characteristics WITHOUT training to get recommendations.
    
    Request body:
        {
            "file_id": str,
            "use_existing_metrics": bool (optional)
        }
    
    Returns:
        {
            "success": bool,
            "analysis": {
                "total_windows": int,
                "coefficient_of_variation": float,
                "variance_type": str,
                "recommended_strategy": str,
                "training_samples_needed": int,
                "estimated_training_time_seconds": float,
                "note": str,
                "dataset_info": {
                    "file_size_mb": float,
                    "duration_seconds": int
                }
            }
        }
    """
    try:
        data = request.get_json() or {}
        file_id = data.get('file_id')
        use_existing = data.get('use_existing_metrics', False)
        
        if not file_id:
            return jsonify({'success': False, 'error': 'file_id required'}), 400
        
        # Load or compute metrics
        metrics_file = os.path.join(current_app.config.get('METRICS_DIR', 'logs'), 'metrics.jsonl')
        
        if use_existing and os.path.exists(metrics_file):
            metrics = load_metrics_jsonl(metrics_file)
        else:
            # Find PCAP file
            upload_dir = current_app.config.get('UPLOAD_DIR', 'data/uploads')
            pcap_path = None
            pcap_size_mb = 0
            
            for f in os.listdir(upload_dir):
                if file_id in f:
                    pcap_path = os.path.join(upload_dir, f)
                    pcap_size_mb = os.path.getsize(pcap_path) / (1024**2)
                    break
            
            if not pcap_path or not os.path.exists(pcap_path):
                return jsonify({'success': False, 'error': 'PCAP file not found'}), 404
            
            # Compute metrics using subprocess
            cmd = [
                sys.executable,
                'scripts/run_metrics.py',
                '--pcap', pcap_path,
                '--out', metrics_file
            ]
            
            result = subprocess.run(
                cmd,
                cwd=os.getcwd(),
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode != 0:
                return jsonify({
                    'success': False,
                    'error': f'Metrics computation failed: {result.stderr}'
                }), 500
            
            metrics = load_metrics_jsonl(metrics_file)
        
        if len(metrics) < 5:
            return jsonify({
                'success': False,
                'error': f'Not enough metric windows: {len(metrics)}'
            }), 400
        
        # Analyze dataset
        analysis = get_dataset_stats(metrics)
        
        # Add file info if available
        if pcap_path:
            analysis['dataset_info'] = {
                'file_size_mb': pcap_size_mb,
                'file_path': os.path.basename(pcap_path)
            }
            
            # Estimate duration from timestamps if available
            if metrics and len(metrics) > 1:
                first_ts = metrics[0].get('timestamp', 0)
                last_ts = metrics[-1].get('timestamp', 0)
                if last_ts > first_ts:
                    duration = last_ts - first_ts
                    analysis['dataset_info']['duration_seconds'] = int(duration)
                    analysis['dataset_info']['metric_windows'] = len(metrics)
        
        return jsonify({
            'success': True,
            'analysis': analysis
        }), 200
    
    except subprocess.TimeoutExpired:
        return jsonify({'success': False, 'error': 'Metrics computation timed out'}), 500
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@training_bp.route('/models', methods=['GET'])
def list_models():
    """List all trained models."""
    try:
        model = IsolationForestModel(
            model_dir=current_app.config.get('MODELS_DIR', 'app/ml/models')
        )
        models = model.list_models()
        
        return jsonify({
            'success': True,
            'models': models,
            'count': len(models)
        }), 200
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@training_bp.route('/models/<model_name>', methods=['DELETE'])
def delete_model(model_name: str):
    """Delete a trained model."""
    try:
        model_dir = current_app.config.get('MODELS_DIR', 'app/ml/models')
        model_path = os.path.join(model_dir, f'{model_name}.pkl')
        meta_path = os.path.join(model_dir, f'{model_name}_metadata.json')
        
        removed = False
        if os.path.exists(model_path):
            os.remove(model_path)
            removed = True
        if os.path.exists(meta_path):
            os.remove(meta_path)
            removed = True
        
        if not removed:
            return jsonify({'success': False, 'error': 'Model not found'}), 404
        
        return jsonify({'success': True, 'message': 'Model deleted'}), 200
    
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500
