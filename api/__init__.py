"""
API Module - REST API for Network Traffic Analyzer

The API provides comprehensive REST endpoints for:
- Metrics: Compute and retrieve traffic metrics
- Anomalies: Detect and view anomalies
- Baselines: Manage baseline profiles
- Control: System control and live capture management

Usage:
    Start API server with PCAP file (development):
    $ PYTHONPATH=. python api/api_server.py --mode pcap --pcap data/raw/pcapng/test_net_traffic.pcapng
    
    Or with live capture (production):
    $ PYTHONPATH=. python api/api_server.py --mode live --interface eth0

Endpoints:
    /health                   - Health check
    /api/status               - System status
    
    /api/metrics              - List metrics
    /api/metrics/:id          - Get specific metric window
    /api/metrics/compute      - Compute metrics from PCAP
    /api/metrics/summary      - Aggregate statistics
    
    /api/anomalies            - List anomalies
    /api/anomalies/detect     - Run anomaly detection
    /api/anomalies/by-type    - Group anomalies by type
    /api/anomalies/top        - Top anomalies
    
    /api/baselines            - List baselines
    /api/baselines/:type      - Get baseline by type
    /api/baselines/generate   - Generate baselines
    /api/baselines/stats      - Baseline statistics
    
    /api/control/status       - Detailed status
    /api/control/config       - API configuration
    /api/control/capture/start  - Start live capture
    /api/control/capture/stop   - Stop live capture
    /api/control/logs         - Get logs
"""

__version__ = '1.0.0'
__all__ = [
    'api_server',
    'routes_metrics',
    'route_anomalies',
    'routes_baselines',
    'routes_control'
]
