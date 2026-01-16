#!/usr/bin/env python3
"""
Feature Extractor for ML Anomaly Detection

Converts raw network metrics into numerical features for machine learning.
"""

import numpy as np
from typing import List, Dict, Any, Tuple, Optional


class FeatureExtractor:
    """Extract ML features from network metrics."""
    
    FEATURES = [
        'bytes_per_second',
        'packets_per_second',
        'avg_latency_ms',
        'latency_p99_ms',
        'tcp_rtt_ms',
        'active_connections',
        'tcp_percent',
        'udp_percent',
        'icmp_percent',
        'avg_packet_size',
    ]
    
    def __init__(self, handle_missing: str = 'mean'):
        self.handle_missing = handle_missing
        self.feature_stats = {}
    
    def extract_features(self, metric_window: Dict[str, Any]) -> np.ndarray:
        """Extract features from a single metric window."""
        features = []
        
        # Bandwidth metrics
        bandwidth = metric_window.get('bandwidth', {})
        features.append(self._get_value(bandwidth, 'avg_bps', 0))
        features.append(self._get_value(bandwidth, 'avg_pps', 0))
        
        # Latency metrics
        latency = metric_window.get('latency', {})
        req_resp = self._get_value(latency, 'request_response', {})
        features.append(self._get_value(req_resp, 'mean', 0))
        features.append(self._get_value(req_resp.get('percentiles', {}), '99', 0))
        
        tcp_rtt = self._get_value(latency, 'tcp_rtt', {})
        features.append(self._get_value(tcp_rtt, 'mean', 0))
        
        # Connection metrics
        connections = metric_window.get('connections', {})
        features.append(self._get_value(connections, 'active_connections', 0))
        
        # Protocol distribution
        protocol = metric_window.get('protocol', {})
        tcp_pct = self._get_value(protocol, 'tcp_percent', 0)
        udp_pct = self._get_value(protocol, 'udp_percent', 0)
        icmp_pct = self._get_value(protocol, 'icmp_percent', 0)
        
        # Normalize to percentages
        total = tcp_pct + udp_pct + icmp_pct
        if total > 0:
            tcp_pct = (tcp_pct / total) * 100
            udp_pct = (udp_pct / total) * 100
            icmp_pct = (icmp_pct / total) * 100
        
        features.append(tcp_pct)
        features.append(udp_pct)
        features.append(icmp_pct)
        
        # Packet size
        features.append(self._get_value(bandwidth, 'avg_packet_size', 0))
        
        return np.array(features, dtype=np.float64)
    
    def extract_batch(self, metric_windows: List[Dict[str, Any]],
                     sample_rate: Optional[float] = None,
                     sampling_strategy: str = 'uniform'
                     ) -> Tuple[np.ndarray, List[int], Dict[str, Any]]:
        """
        Extract features from multiple metric windows with optional sampling.
        
        Args:
            metric_windows: List of metric window dicts
            sample_rate: Fraction of data to use (0.0-1.0). None = use all data.
            sampling_strategy: 'uniform', 'stratified', or 'systematic'
                - uniform: random sampling
                - stratified: divide into chunks, sample from each
                - systematic: take every Nth sample
        
        Returns:
            X: Feature matrix (n_samples, n_features)
            valid_indices: Original indices of selected samples
            stats: Dict with sampling info {total_windows, selected_samples, sample_rate_actual, strategy}
        """
        features_list = []
        valid_indices_full = []
        
        # First pass: extract all valid features
        for i, window in enumerate(metric_windows):
            try:
                features = self.extract_features(window)
                if np.isfinite(features).all() and np.any(features != 0):
                    features_list.append(features)
                    valid_indices_full.append(i)
            except Exception:
                continue
        
        if not features_list:
            return (
                np.array([]).reshape(0, len(self.FEATURES)), 
                [],
                {
                    'total_windows': len(metric_windows),
                    'selected_samples': 0,
                    'sample_rate_actual': 0.0,
                    'strategy': sampling_strategy
                }
            )
        
        # Apply sampling if needed
        selected_indices = list(range(len(features_list)))
        
        if sample_rate is not None and 0 < sample_rate < 1.0:
            n_select = max(1, int(len(features_list) * sample_rate))
            
            if sampling_strategy == 'uniform':
                # Random sampling without replacement
                selected_indices = sorted(
                    np.random.choice(len(features_list), n_select, replace=False)
                )
            
            elif sampling_strategy == 'stratified':
                # Divide into chunks, sample proportionally from each
                n_chunks = max(5, int(len(features_list) ** 0.5))
                chunk_size = len(features_list) // n_chunks
                selected_indices = []
                
                for chunk_idx in range(n_chunks):
                    start = chunk_idx * chunk_size
                    end = start + chunk_size if chunk_idx < n_chunks - 1 else len(features_list)
                    chunk_samples = max(1, int((end - start) * sample_rate))
                    
                    chunk_indices = np.random.choice(
                        list(range(start, end)),
                        min(chunk_samples, end - start),
                        replace=False
                    )
                    selected_indices.extend(chunk_indices)
                
                selected_indices = sorted(selected_indices[:n_select])
            
            elif sampling_strategy == 'systematic':
                # Take every Nth sample
                step = max(1, len(features_list) // n_select)
                selected_indices = list(range(0, len(features_list), step))[:n_select]
        
        # Extract selected features and map back to original indices
        X = np.array([features_list[i] for i in selected_indices])
        valid_indices = [valid_indices_full[i] for i in selected_indices]
        
        actual_rate = len(selected_indices) / len(features_list) if features_list else 0.0
        
        stats = {
            'total_windows': len(metric_windows),
            'valid_samples_found': len(features_list),
            'selected_samples': len(selected_indices),
            'sample_rate_requested': sample_rate,
            'sample_rate_actual': actual_rate,
            'strategy': sampling_strategy,
            'reduction_percent': round((1 - actual_rate) * 100, 1)
        }
        
        return X, valid_indices, stats
    
    def normalize(self, X: np.ndarray, fit: bool = False) -> np.ndarray:
        """Normalize features to zero mean and unit variance."""
        if fit:
            self.feature_stats = {
                'mean': X.mean(axis=0),
                'std': X.std(axis=0) + 1e-8,
            }
        
        if not self.feature_stats:
            return X
        
        mean = self.feature_stats.get('mean', 0)
        std = self.feature_stats.get('std', 1)
        
        return (X - mean) / std
    
    @staticmethod
    def _get_value(d: Dict[str, Any], key: str, default: Any = None) -> Any:
        """Safely extract values from dict."""
        if isinstance(d, dict) and key in d and d[key] is not None:
            return d[key]
        return default
    
    def get_feature_names(self) -> List[str]:
        """Get list of feature names."""
        return self.FEATURES.copy()
    
    @staticmethod
    def recommend_sample_rate(total_samples: int) -> Dict[str, Any]:
        """
        Recommend optimal sampling strategy based on dataset size.
        
        Isolation Forest trains effectively with 500-5000 samples.
        More samples improve anomaly detection but increase training time.
        """
        recommendations = {
            'total_samples': total_samples,
            'recommendation': 'use_all' if total_samples <= 5000 else 'sample',
            'suggested_rate': None,
            'reasoning': ''
        }
        
        if total_samples <= 500:
            recommendations['suggested_rate'] = 1.0
            recommendations['reasoning'] = 'Dataset is small; use all samples for better model'
        elif total_samples <= 5000:
            recommendations['suggested_rate'] = 1.0
            recommendations['reasoning'] = 'Dataset size is optimal for Isolation Forest (500-5000 range)'
        elif total_samples <= 10000:
            recommendations['suggested_rate'] = 0.8
            recommendations['reasoning'] = 'Slightly large; use 80% to reduce training time while maintaining accuracy'
        elif total_samples <= 50000:
            recommendations['suggested_rate'] = 0.5
            recommendations['reasoning'] = 'Use 50% (uniform sampling) to get ~5000 samples; captures data distribution'
        else:
            recommendations['suggested_rate'] = 0.25
            recommendations['reasoning'] = f'Very large dataset ({total_samples} samples); use 25% for efficiency'
        
        return recommendations
