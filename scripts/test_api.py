#!/usr/bin/env python3
"""
API Integration Test Script

Tests all major endpoints of the Network Traffic Analyzer API.
"""

import requests
import json
import time
from typing import Dict, Any

BASE_URL = 'http://127.0.0.1:5000'
ENDPOINTS = {
    'health': '/health',
    'status': '/api/status',
    'control_status': '/api/control/status',
    'control_config': '/api/control/config',
    'control_ping': '/api/control/ping',
    'metrics_list': '/api/metrics/',
    'metrics_summary': '/api/metrics/summary',
    'metrics_compute': '/api/metrics/compute',
    'anomalies_list': '/api/anomalies/',
    'anomalies_by_type': '/api/anomalies/by-type',
    'anomalies_top': '/api/anomalies/top',
    'anomalies_detect': '/api/anomalies/detect',
    'baselines_list': '/api/baselines/',
    'baselines_bandwidth': '/api/baselines/bandwidth',
    'baselines_stats': '/api/baselines/stats',
}


def test_endpoint(name: str, method: str, url: str, data: Dict[str, Any] = None, show_response: bool = True) -> bool:
    """Test a single endpoint."""
    full_url = BASE_URL + url
    try:
        if method == 'GET':
            response = requests.get(full_url, timeout=5)
        elif method == 'POST':
            response = requests.post(full_url, json=data, timeout=5)
        else:
            return False
        
        status = "✓" if response.status_code == 200 else "✗"
        print(f"{status} [{response.status_code}] {name}")
        
        if show_response and response.text:
            try:
                resp_json = response.json()
                if isinstance(resp_json, dict):
                    # Show limited keys
                    keys = list(resp_json.keys())[:3]
                    print(f"    Keys: {', '.join(keys)}")
                    if 'total' in resp_json:
                        print(f"    Total items: {resp_json.get('total')}")
                    if 'count' in resp_json:
                        print(f"    Count: {resp_json.get('count')}")
            except:
                pass
        
        return response.status_code == 200
    
    except requests.exceptions.ConnectionError:
        print(f"✗ [{name}] Connection error - API server not running")
        return False
    except requests.exceptions.Timeout:
        print(f"✗ [{name}] Timeout")
        return False
    except Exception as e:
        print(f"✗ [{name}] {str(e)}")
        return False


def main():
    """Run all tests."""
    print("\n" + "="*70)
    print("Network Traffic Analyzer - API Integration Test")
    print("="*70 + "\n")
    
    results = {}
    
    # Health & Status Tests
    print("Health & Status Endpoints:")
    print("-" * 70)
    results['health'] = test_endpoint("Health Check", "GET", ENDPOINTS['health'])
    results['status'] = test_endpoint("API Status", "GET", ENDPOINTS['status'])
    results['control_status'] = test_endpoint("Control Status", "GET", ENDPOINTS['control_status'])
    results['control_config'] = test_endpoint("Control Config", "GET", ENDPOINTS['control_config'])
    results['control_ping'] = test_endpoint("Control Ping", "GET", ENDPOINTS['control_ping'])
    
    print("\nMetrics Endpoints:")
    print("-" * 70)
    results['metrics_list'] = test_endpoint("Metrics List", "GET", ENDPOINTS['metrics_list'])
    results['metrics_summary'] = test_endpoint("Metrics Summary", "GET", ENDPOINTS['metrics_summary'])
    
    print("\nAnomalies Endpoints:")
    print("-" * 70)
    results['anomalies_list'] = test_endpoint("Anomalies List", "GET", ENDPOINTS['anomalies_list'])
    results['anomalies_by_type'] = test_endpoint("Anomalies by Type", "GET", ENDPOINTS['anomalies_by_type'])
    results['anomalies_top'] = test_endpoint("Top Anomalies", "GET", ENDPOINTS['anomalies_top'])
    
    print("\nBaselines Endpoints:")
    print("-" * 70)
    results['baselines_list'] = test_endpoint("Baselines List", "GET", ENDPOINTS['baselines_list'])
    results['baselines_bandwidth'] = test_endpoint("Baseline (Bandwidth)", "GET", ENDPOINTS['baselines_bandwidth'])
    results['baselines_stats'] = test_endpoint("Baselines Stats", "GET", ENDPOINTS['baselines_stats'])
    
    print("\nComputation Endpoints (POST):")
    print("-" * 70)
    results['metrics_compute'] = test_endpoint(
        "Compute Metrics (cached)",
        "POST",
        ENDPOINTS['metrics_compute'],
        {"force": False}
    )
    results['anomalies_detect'] = test_endpoint(
        "Detect Anomalies (cached)",
        "POST",
        ENDPOINTS['anomalies_detect'],
        {"force": False}
    )
    
    # Summary
    print("\n" + "="*70)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"Test Results: {passed}/{total} endpoints passed")
    print("="*70 + "\n")
    
    # Detailed status report
    print("Endpoint Status Summary:")
    for name, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status:8} - {name}")


if __name__ == '__main__':
    main()
