# ML Model Training - Training Data Processing

## Training Dataset Info
- **File**: data/training_data/202601011400.pcap
- **Size**: 9.7 GB
- **Duration**: 900 seconds (15 minutes)
- **Packets**: 150.99 million
- **Average Bitrate**: 811.52 Mbps (±360.56 Mbps std dev)

## Processing Pipeline

### Step 1: Metrics Extraction (In Progress)
Currently running: `scripts/extract_metrics_fast.py`

This script uses **tshark** (Wireshark CLI) to rapidly extract packets and compute windowed metrics:
- Reads all 150M packets from PCAP
- Groups packets into 10-second windows
- Computes per-window metrics:
  - **Bandwidth**: avg_bps, avg_pps
  - **Latency**: request-response times, TCP RTT
  - **Connections**: active connection counts
  - **Protocol Distribution**: TCP%, UDP%, ICMP%
  - **Packet Size**: average packet size

**Expected Output**:
- `logs/training_metrics.jsonl` - ~90 metric windows (one per 10-second interval)
- Each window contains aggregated traffic statistics
- File size: ~1-5 MB

**Estimated Time**: 10-30 minutes (depends on disk I/O)

### Step 2: Feature Extraction (After metrics ready)
Once metrics are extracted, convert to ML features:
```bash
python scripts/analyze_dataset.py --metrics logs/training_metrics.jsonl
```

This will:
- Load 90 metric windows
- Extract 10 ML features per window
- Analyze dataset characteristics (mean, variance)
- Recommend optimal sampling strategy

### Step 3: Model Training (After features ready)
Train the Isolation Forest model:
```python
# Via API
POST /api/train
{
    "model_name": "isolation_forest_v1",
    "metrics_file": "logs/training_metrics.jsonl"
}

# Via Python
from app.ml import IsolationForestModel, FeatureExtractor
extractor = FeatureExtractor()
X, indices, info = extractor.extract_batch(metrics)
model = IsolationForestModel(contamination=0.05)
model.train(X)
model.save("models/isolation_forest_v1.pkl")
```

**Expected Training Time**: 1-5 seconds (Isolation Forest is fast)
**Model Size**: 1-10 MB (joblib pickle)

### Step 4: Anomaly Detection
Use trained model on new data:
```python
# Load model
model = IsolationForestModel.load("models/isolation_forest_v1.pkl")

# Get predictions with human insights
results = model.predict_with_insights(X_test)

# Each result includes:
{
    'index': 42,
    'is_anomaly': True,
    'severity': 'high',
    'message': 'High anomaly detected (confidence: 87.3%)',
    'anomaly_probability': 0.873,
    'anomaly_score': -2.45,
    'features': {...}
}
```

## What's Happening Now

1. **tshark** is parsing 150.99 million packets
2. Grouping them into 10-second time windows
3. Computing aggregate metrics per window
4. Writing to `logs/training_metrics.jsonl`

Progress indicators show:
- Packet count processed
- Packets per second (pps)
- Total extraction time

## Files Created

- `scripts/extract_metrics_fast.py` - Fast metric extraction using tshark
- `scripts/extract_metrics_sampled.py` - Alternative with packet sampling (slower)

## Feature Set for ML Model

After metrics extraction, the model will use these 10 features:

1. **bytes_per_second** - Average throughput in bytes/sec
2. **packets_per_second** - Average packet rate
3. **avg_latency_ms** - Mean request-response latency
4. **latency_p99_ms** - 99th percentile latency
5. **tcp_rtt_ms** - TCP round-trip time
6. **active_connections** - Concurrent connection count
7. **tcp_percent** - TCP traffic percentage
8. **udp_percent** - UDP traffic percentage
9. **icmp_percent** - ICMP traffic percentage
10. **avg_packet_size** - Average packet size in bytes

## Next Steps (Manual)

When metrics extraction completes, run:

```bash
# 1. Analyze dataset
python scripts/analyze_dataset.py --metrics logs/training_metrics.jsonl

# 2. Start API server
python -m app.main

# 3. Train model via API
curl -X POST http://localhost:5000/api/train \
  -H "Content-Type: application/json" \
  -d '{
    "model_name": "isolation_forest_v1",
    "metrics_file": "logs/training_metrics.jsonl",
    "contamination": 0.05
  }'

# 4. Check model status
curl http://localhost:5000/api/models

# 5. Run detection on test data
curl -X POST http://localhost:5000/api/anomalies/detect \
  -H "Content-Type: application/json" \
  -d '{"metrics_file": "logs/training_metrics.jsonl"}'
```

## Performance Notes

- **Extraction**: 150M packets on 9.7GB file → 10-30 minutes
- **Feature Extraction**: 90 windows × 10 features → <1 second
- **Model Training**: Isolation Forest on 90 samples → 1-5 seconds
- **Prediction**: Per-window anomaly detection → <0.1ms per window
- **Total Time to First Insights**: ~15-35 minutes

This is a one-time setup cost. After training, detection is real-time with 10-second latency windows.
