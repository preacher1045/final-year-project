# Network Traffic Analyzer - Backend

Backend infrastructure for the Smart Network Traffic Analyzer system.

## Structure

```
backend/
├── app/                    # Core application logic
│   ├── analysis/          # Traffic analysis modules
│   ├── baselines/         # Baseline configurations
│   ├── capture/           # PCAP loading utilities
│   ├── ml/               # Machine learning models
│   │   ├── models/       # Trained model storage
│   │   ├── isolation_forest_model.py
│   │   └── feature_extractor.py
│   ├── parsing/          # Protocol parsers
│   └── main.py           # Main application entry
├── api/                   # REST API server
│   ├── api_server.py     # Flask application
│   ├── route_anomalies.py
│   ├── route_training.py
│   ├── route_upload.py
│   └── routes_control.py
├── scripts/               # Utility scripts
│   ├── extract_metrics_fast.py
│   ├── extract_metrics_sampled.py
│   └── generate_baselines.py
├── config/                # Configuration files
├── data/                  # Data storage
│   ├── raw/pcapng/       # Raw PCAP files
│   └── uploads/          # Uploaded files
├── logs/                  # Log files
│   ├── app.log           # Application logs
│   ├── metrics.jsonl     # Extracted metrics
│   └── anomalies.jsonl   # Detected anomalies
└── requirements.txt       # Python dependencies

```

## Quick Start

### Install Dependencies
```bash
cd backend
pip install -r requirements.txt
```

### Run API Server
```bash
cd ..  # Go to project root
PYTHONPATH=backend python backend/api/api_server.py --mode pcap --pcap backend/data/raw/pcapng/test_net_traffic.pcapng
```

### Extract Metrics
```bash
python backend/scripts/extract_metrics_fast.py --pcap backend/data/raw/pcapng/test_net_traffic.pcapng --out backend/logs/metrics.jsonl
```

### Train Model
```bash
python -c "
import sys
sys.path.insert(0, 'backend')
from app.ml import IsolationForestModel, FeatureExtractor
import json

# Load metrics
metrics = []
with open('backend/logs/metrics.jsonl') as f:
    for line in f:
        if line.strip():
            metrics.append(json.loads(line))

# Extract features and train
extractor = FeatureExtractor()
X, indices, stats = extractor.extract_batch(metrics)
model = IsolationForestModel()
model.train(X, extractor.FEATURES, 'my_model')
"
```

## API Endpoints

- `GET /health` - Health check
- `GET /api/status` - System status
- `GET /api/anomalies` - List anomalies
- `POST /api/anomalies/detect` - Run detection
- `GET /api/anomalies/summary` - Anomaly statistics
- `POST /api/upload` - Upload PCAP file
- `POST /api/train` - Train ML model

See [API Documentation](../API_DOCUMENTATION.md) for details.
