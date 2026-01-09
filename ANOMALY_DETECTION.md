# Network Traffic Anomaly Detection System

## Overview

Complete anomaly detection engine implementing 6 statistical detection rules based on explicit thresholds (not vague AI claims).

## Detectors Implemented

### A. Traffic Spike Detection ✅
**File:** `app/anomalies/traffic_spike_detector.py`

- **Rule:** Bₜ > μ + 3σ (high), Bₜ > μ + 2σ (medium)
- **Metric:** Bytes per second (Bps)
- **Status:** Active — Detected 5 anomalies in test run

Example detection:
```
"High traffic spike detected: 549460.0 Bps (threshold: 397795.0 Bps)"
"Deviation: 307.7% above baseline"
```

---

### B. Port Scanning Detection ✅
**File:** `app/anomalies/scan_detector.py`

- **Rule:** Both conditions met:
  - SYN count > 100 within 60-second window
  - Destination ports contacted > 20
- **Status:** Framework implemented
- **Note:** Requires flow-level enrichment (future enhancement with extended metrics)

---

### C. High Latency Detection ✅
**File:** `app/anomalies/latency_anomaly_detection.py`

- **Rule:** 
  - High: RTT > 2 × baseline
  - Medium: RTT > 1.5 × baseline
- **Metrics:** TCP RTT (ms) and request-response latency (ms)
- **Status:** Active — Detected 6 anomalies in test run

Example detection:
```
"High request-response latency detected: 255.42 ms (threshold: 153.42 ms)"
"Deviation: 233.0% above baseline"
"baseline_mean: 76.71 ms"
```

---

### D. Packet Loss Detection ✅
**File:** `app/anomalies/packet_loss_detection.py`

- **Rule:**
  - High: Packet loss > 5%
  - Medium: Packet loss > 2%
- **Formula:** Packet Loss (%) = (Sent - Received) / Sent × 100
- **Status:** Framework implemented
- **Note:** Requires TCP retransmission tracking (future enhancement)

---

### E. Protocol Anomaly Detection ✅
**File:** `app/anomalies/protocol_anomaly_detection.py`

- **Rule:** |P_current - P_normal| > 30%
- **Metric:** Protocol distribution percentage change
- **Status:** Active (no anomalies in test window)
- **Example:** UDP increases from 10% → 50% of total traffic

---

### F. Long-Lived Connections Detection ✅
**File:** `app/anomalies/long_lived_connections.py`

- **Rules:**
  - High: Duration > 2 × baseline mean
  - Medium: Duration > 1.5 × baseline mean
  - Idle: Long duration (>1.5× baseline) with low throughput (<1000 bytes)
- **Status:** Active — Detected 1 anomaly in test run

Example:
```
"Moderately long connections detected: avg 0.22s duration (baseline: 0.14s)"
"Deviation: 55.2% above baseline"
```

---

## Core Engine

**File:** `app/anomalies/anomaly_engine.py`

### Features:
- **Unified Interface:** Orchestrates all 6 detectors
- **Baseline Loading:** Auto-loads JSON baselines from `app/baselines/`
- **Batch Analysis:** Processes entire JSONL metric files
- **Result Export:** Writes anomalies to `logs/anomalies.jsonl`
- **Statistics:** Aggregates by type and severity

### Usage:
```bash
PYTHONPATH=. python3 -m app.anomalies.anomaly_engine
```

### Output Format:
```json
{
  "window_start": 1767897432.716141,
  "window_end": 1767897442.716141,
  "timestamp": "2026-01-09T14:26:23.976589",
  "anomaly_count": 1,
  "anomalies": [
    {
      "type": "high_latency",
      "severity": "high",
      "metric": "request_response_ms",
      "threshold": 153.42,
      "current_value": 255.42,
      "deviation": "233.0% above baseline",
      "message": "High request-response latency detected: 255.42 ms",
      "baseline_mean": 76.71,
      "sample_count": 36
    }
  ],
  "summary": {
    "by_type": { "high_latency": { "medium": 0, "high": 1 } },
    "by_severity": { "medium": 0, "high": 1 }
  }
}
```

---

## Test Results (25 metric windows)

```
Total windows analyzed: 25
Windows with anomalies: 11 (44.0%)
Total anomalies detected: 12

Anomalies by type:
  high_latency: 6 (medium: 4, high: 2)
  traffic_spike: 5 (medium: 2, high: 3)
  long_lived_conn: 1 (medium: 1, high: 0)

By severity: Medium: 7, High: 5
```

---

## Integration Points

### Input:
- **Metric Windows:** `logs/metrics.jsonl` (from `scripts/run_metrics.py`)
- **Baselines:** `app/baselines/baseline_*.json` (from `scripts/generate_baselines.py`)

### Output:
- **Anomaly Results:** `logs/anomalies.jsonl`

### Dependencies:
- Baseline files must exist and be properly formatted
- Metric windows must include required fields (bandwidth, latency, connections, protocol)

---

## Future Enhancements

### Priority 1: Flow-Level Enrichment
- Port scanning (Rule B): Requires per-flow SYN tracking
- Packet loss (Rule D): Requires TCP retransmission analysis
- Solution: Extend metrics pipeline to include flow-level packet analysis

### Priority 2: Real-Time Streaming
- Adapt engine for live metric windows
- Add alert/notification hooks
- Support time-series DB export (InfluxDB, Prometheus)

### Priority 3: Advanced Rules
- Machine learning ensemble (unsupervised anomaly scoring)
- Correlation detection (multi-metric anomalies)
- Behavioral baselining per source/destination IP

### Priority 4: Visualization
- Grafana dashboard for anomaly alerts
- Time-series plots of metrics vs. anomalies
- Top anomaly sources/destinations

---

## Design Philosophy

✅ **Explicit Rules** — All thresholds clearly stated (no black-box ML)  
✅ **Statistical Grounding** — Rules derive from baselines + standard deviations  
✅ **Severity Levels** — Medium/High classification for triage  
✅ **Explainable Outputs** — Every anomaly includes deviation % and threshold  
✅ **Extensible** — Easy to add new detectors following same pattern  

