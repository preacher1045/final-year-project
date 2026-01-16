"""
Machine Learning Module for Network Traffic Anomaly Detection

This module provides ML-based anomaly detection using Isolation Forest.
Replaces rule-based detection with a data-driven approach.
"""

from .isolation_forest_model import IsolationForestModel, ModelMetadata
from .feature_extractor import FeatureExtractor

__all__ = ['IsolationForestModel', 'FeatureExtractor', 'ModelMetadata']
__version__ = '1.0.0'
