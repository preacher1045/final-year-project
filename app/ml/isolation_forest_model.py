#!/usr/bin/env python3
"""
Isolation Forest Anomaly Detection Model

ML-based anomaly detection using sklearn's Isolation Forest algorithm.
"""

import json
import os
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
import numpy as np
from sklearn.ensemble import IsolationForest # type: ignore
import joblib # type: ignore


class ModelMetadata:
    """Metadata for trained models."""
    
    def __init__(self, model_name: str, training_samples: int, 
                 contamination: float = 0.1, feature_names: List[str] = None):
        self.model_name = model_name
        self.training_samples = training_samples
        self.contamination = contamination
        self.feature_names = feature_names or []
        self.created_at = datetime.utcnow().isoformat()
        self.updated_at = self.created_at
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            'model_name': self.model_name,
            'training_samples': self.training_samples,
            'contamination': self.contamination,
            'feature_names': self.feature_names,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
        }


class IsolationForestModel:
    """
    Isolation Forest model wrapper for anomaly detection.
    
    Identifies outliers in network traffic patterns by isolating observations
    that are few and different from the rest of the dataset.
    """
    
    def __init__(self, contamination: float = 0.1, n_estimators: int = 100,
                 random_state: int = 42, model_dir: str = 'app/ml/models'):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state
        self.model_dir = model_dir
        self.metadata = None
        self.feature_names = None
        self.model: Optional[IsolationForest] = None
        self.is_trained = False
        
        os.makedirs(model_dir, exist_ok=True)
    
    def train(self, X: np.ndarray, feature_names: List[str], 
              model_name: str = 'default') -> Dict[str, Any]:
        """Train the Isolation Forest model."""
        if X.shape[0] < 10:
            raise ValueError(f"Need at least 10 samples, got {X.shape[0]}")
        
        self.feature_names = feature_names
        self.model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
            n_jobs=-1
        )
        
        self.model.fit(X)
        self.is_trained = True
        
        self.metadata = ModelMetadata(
            model_name=model_name,
            training_samples=X.shape[0],
            contamination=self.contamination,
            feature_names=feature_names,
        )
        
        self.save(model_name)
        
        predictions = self.model.predict(X)
        anomaly_count = np.sum(predictions == -1)
        
        return {
            'success': True,
            'model_name': model_name,
            'training_samples': X.shape[0],
            'n_features': X.shape[1],
            'anomalies_detected': int(anomaly_count),
            'anomaly_rate': float(anomaly_count / X.shape[0]),
            'contamination': self.contamination,
            'timestamp': datetime.utcnow().isoformat(),
        }
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """Predict anomalies in the data."""
        if not self.is_trained or self.model is None:
            raise RuntimeError("Model must be trained before prediction")
        
        predictions = self.model.predict(X)
        scores = self.model.score_samples(X)
        
        # Normalize scores to probabilities [0, 1]
        min_score = scores.min()
        max_score = scores.max()
        range_score = max_score - min_score if max_score > min_score else 1.0
        
        # Invert: lower score = higher probability of anomaly
        probabilities = 1.0 - ((scores - min_score) / range_score)
        probabilities = np.clip(probabilities, 0.0, 1.0)
        
        return predictions, scores, probabilities
    
    def predict_with_insights(self, X: np.ndarray, data_indices: List[int] = None
                             ) -> List[Dict[str, Any]]:
        """Predict anomalies with human-readable insights."""
        predictions, scores, probs = self.predict(X)
        results = []
        
        for i, (pred, score, prob) in enumerate(zip(predictions, scores, probs)):
            is_anomaly = pred == -1
            severity = self._calculate_severity(prob)
            
            result = {
                'index': data_indices[i] if data_indices else i,
                'is_anomaly': bool(is_anomaly),
                'anomaly_score': float(score),
                'anomaly_probability': float(prob),
                'severity': severity,
                'message': self._generate_message(is_anomaly, prob, severity),
                'features': {
                    name: float(X[i, j]) 
                    for j, name in enumerate(self.feature_names or [])
                }
            }
            results.append(result)
        
        return results
    
    def _calculate_severity(self, probability: float) -> str:
        """Determine severity from anomaly probability."""
        if probability < 0.5:
            return 'low'
        elif probability < 0.75:
            return 'medium'
        else:
            return 'high'
    
    def _generate_message(self, is_anomaly: bool, prob: float, severity: str) -> str:
        """Generate human-readable message."""
        if not is_anomaly:
            return 'Normal traffic pattern detected'
        return f'{severity.capitalize()} anomaly detected (confidence: {prob*100:.1f}%)'
    
    def save(self, model_name: str = 'default') -> str:
        """Save trained model and metadata to disk."""
        if not self.is_trained or self.model is None:
            raise RuntimeError("Model must be trained before saving")
        
        model_path = os.path.join(self.model_dir, f'{model_name}.pkl')
        metadata_path = os.path.join(self.model_dir, f'{model_name}_metadata.json')
        
        joblib.dump(self.model, model_path)
        
        metadata = self.metadata.to_dict() if self.metadata else {
            'model_name': model_name,
            'feature_names': self.feature_names or [],
            'saved_at': datetime.utcnow().isoformat(),
        }
        with open(metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        return model_path
    
    def load(self, model_name: str = 'default') -> bool:
        """Load trained model from disk."""
        model_path = os.path.join(self.model_dir, f'{model_name}.pkl')
        metadata_path = os.path.join(self.model_dir, f'{model_name}_metadata.json')
        
        if not os.path.exists(model_path):
            return False
        
        try:
            self.model = joblib.load(model_path)
            self.is_trained = True
            
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    meta_dict = json.load(f)
                    self.feature_names = meta_dict.get('feature_names', [])
                    self.metadata = ModelMetadata(
                        model_name=meta_dict.get('model_name', model_name),
                        training_samples=meta_dict.get('training_samples', 0),
                        contamination=meta_dict.get('contamination', 0.1),
                        feature_names=self.feature_names,
                    )
            
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
    
    def list_models(self) -> List[Dict[str, Any]]:
        """List all available trained models."""
        models = []
        if not os.path.exists(self.model_dir):
            return models
        
        for filename in os.listdir(self.model_dir):
            if filename.endswith('_metadata.json'):
                model_name = filename.replace('_metadata.json', '')
                filepath = os.path.join(self.model_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        meta = json.load(f)
                        meta['model_name'] = model_name
                        models.append(meta)
                except Exception:
                    pass
        
        return models
