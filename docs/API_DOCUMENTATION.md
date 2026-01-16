# Network Traffic Analyzer - REST API Documentation

## Overview

The Network Traffic Analyzer API provides comprehensive REST endpoints for analyzing network traffic, detecting anomalies, and managing baselines. The API supports both PCAP file analysis (development) and live traffic capture (production).

**Base URL:** `http://localhost:5000`

## Quick Start

### Start API Server (PCAP Mode - Development)

```bash
PYTHONPATH=. python3 api/api_server.py --mode pcap --pcap data/raw/pcapng/test_net_traffic.pcapng
```

### Start API Server (Live Mode - Production)

```bash
# Requires sudo for network interface access
sudo PYTHONPATH=. python3 api/api_server.py --mode live --interface eth0
```

## Health & Status Endpoints

### GET /health
Simple health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "timestamp": "2026-01-09T17:41:06.493726",
  "mode": "pcap",
  "version": "1.0.0"
}
```

---

### GET /api/status
Get API and system status with data availability.

**Response:**
```json
{
  "api": {
    "status": "running",
    "version": "1.0.0",
    "timestamp": "2026-01-09T17:41:06.493726"
  },
  "system": {
    "mode": "pcap",
    "pcap_file": "data/raw/pcapng/test_net_traffic.pcapng",
    "interface": null,
    "window_size": 10,
    "metrics_dir": "logs",
    "baselines_dir": "app/baselines"
  },
  "data": {
    "metrics": true,
    "baselines": true,
    "anomalies": true
  }
}
```

---

### GET /api/control/status
Get detailed system and capture status.

**Response:**
```json
{
  "api": {
    "status": "running",
    "mode": "pcap",
    "version": "1.0.0"
  },
  "system": {
    "python_version": "3.10.12",
    "platform": "linux",
    "tshark_available": true,
    "project_structure": {...}
  },
  "data": {
    "metrics": true,
    "anomalies": true,
    "baselines": false,
    "metric_count": 25,
    "anomaly_count": 25
  },
  "capture": {
    "running": false,
    "start_time": null,
    "interface": null
  }
}
```

---

### GET /api/control/config
Get current API configuration.

**Response:**
```json
{
  "mode": "pcap",
  "pcap_file": "data/raw/pcapng/test_net_traffic.pcapng",
  "interface": null,
  "window_size": 10,
  "directories": {
    "metrics": "logs",
    "baselines": "app/baselines",
    "anomalies": "logs"
  }
}
```

---

### GET /api/control/ping
Simple ping test.

**Response:**
```json
{
  "pong": true,
  "timestamp": "2026-01-09T17:43:23.523582"
}
```

---

## Metrics Endpoints

### GET /api/metrics/
List all computed metric windows.

**Query Parameters:**
- `limit` (int, default=50): Max windows to return
- `offset` (int, default=0): Skip N windows

**Response:**
```json
{
  "count": 25,
  "total": 25,
  "offset": 0,
  "limit": 50,
  "metrics": [
    {
      "window_start": 1234567890.5,
      "window_end": 1234567900.5,
      "bandwidth": {
        "avg_bps": 9568.5,
        "avg_pps": 87.9,
        "duration_s": 9.9,
        "top_src_bytes": [...],
        "top_dst_bytes": [...]
      },
      "latency": {
        "mean_rtt": 45.2,
        "max_rtt": 120.5,
        "p95_rtt": 90.1
      },
      "connections": {
        "total": 42,
        "protocols": {...}
      },
      "protocol": {...},
      "record_count": 362
    }
  ]
}
```

---

### GET /api/metrics/:window_id
Get metrics for a specific window (0-indexed).

**Response:**
```json
{
  "window_id": 0,
  "window_start": 1234567890.5,
  "window_end": 1234567900.5,
  "bandwidth": {...},
  "latency": {...},
  "connections": {...},
  "protocol": {...}
}
```

**Error (404):**
```json
{
  "error": "Window not found",
  "window_id": 999,
  "total_windows": 25
}
```

---

### GET /api/metrics/summary
Get aggregate statistics across all windows.

**Response:**
```json
{
  "total_windows": 25,
  "time_span": 250.5,
  "bandwidth": {
    "mean_bps": 9500.0,
    "max_bps": 15000.0,
    "min_bps": 2000.0
  },
  "latency": {
    "mean_rtt": 45.2,
    "max_rtt": 250.0
  },
  "connections": {
    "total_across_windows": 1050,
    "mean_per_window": 42.0
  }
}
```

---

### POST /api/metrics/compute
Trigger metrics computation from PCAP file or live capture.

**Request Body:**
```json
{
  "source": "pcap",
  "pcap_file": "data/raw/pcapng/test_net_traffic.pcapng",
  "window_size": 10,
  "force": false
}
```

**Response:**
```json
{
  "success": true,
  "message": "Metrics computed successfully",
  "metrics_file": "logs/metrics.jsonl",
  "window_count": 25,
  "window_size": 10,
  "computation_time": 2.45,
  "timestamp": "2026-01-09T17:44:26.123456"
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "PCAP file not found: invalid/path.pcapng"
}
```

---

## Anomalies Endpoints

### GET /api/anomalies/
List all detected anomalies.

**Query Parameters:**
- `type` (str, optional): Filter by anomaly type
  - `traffic_spike`
  - `port_scan`
  - `high_latency`
  - `packet_loss`
  - `protocol_anomaly`
  - `long_lived_conn`
- `severity` (str, optional): Filter by severity (`medium` or `high`)
- `limit` (int, default=100): Max anomalies to return
- `offset` (int, default=0): Skip N anomalies

**Example URL:** `GET /api/anomalies/?type=packet_loss&severity=high&limit=20`

**Response:**
```json
{
  "count": 3,
  "total": 12,
  "offset": 0,
  "limit": 100,
  "filters": {
    "type": "packet_loss",
    "severity": "high"
  },
  "anomalies": [
    {
      "type": "packet_loss",
      "severity": "high",
      "window_start": 1234567890.5,
      "window_end": 1234567900.5,
      "message": "High packet loss detected: 83.33% (5 retrans / 6 sent)",
      "metric": "packet_loss_percent",
      "current_value": 83.33,
      "flow_src": "10.0.15.35:51148",
      "flow_dst": "192.178.223.188:5228",
      "threshold": 70.0
    }
  ]
}
```

---

### GET /api/anomalies/by-type
Get anomalies grouped by type with severity breakdown.

**Response:**
```json
{
  "total": 25,
  "by_type": {
    "packet_loss": {
      "count": 12,
      "by_severity": {
        "high": 10,
        "medium": 2
      }
    },
    "high_latency": {
      "count": 8,
      "by_severity": {
        "medium": 5,
        "high": 3
      }
    },
    "traffic_spike": {
      "count": 5,
      "by_severity": {
        "medium": 3,
        "high": 2
      }
    }
  }
}
```

---

### GET /api/anomalies/window/:window_id
Get anomalies for a specific metric window.

**Response:**
```json
{
  "window_id": 0,
  "count": 2,
  "anomalies": [...]
}
```

---

### GET /api/anomalies/top
Get most frequently occurring anomalies.

**Query Parameters:**
- `limit` (int, default=10): Number of top anomalies to return

**Response:**
```json
{
  "top": [
    {
      "type": "packet_loss",
      "severity": "high",
      "message": "High packet loss detected: 83.33%...",
      "count": 5,
      "first_seen": 1234567890.5,
      "last_seen": 1234567950.5
    }
  ]
}
```

---

### POST /api/anomalies/detect
Trigger anomaly detection on computed metrics.

**Request Body:**
```json
{
  "force": false,
  "window_start": null,
  "window_end": null
}
```

**Response:**
```json
{
  "success": true,
  "message": "Anomaly detection completed",
  "anomalies_file": "logs/anomalies.jsonl",
  "anomaly_count": 25,
  "detection_time": 1.23,
  "summary": {
    "by_type": {
      "packet_loss": 12,
      "high_latency": 8,
      "traffic_spike": 5
    },
    "by_severity": {
      "high": 10,
      "medium": 15
    }
  },
  "timestamp": "2026-01-09T17:44:27.456789"
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "Metrics not found. Run /api/metrics/compute first."
}
```

---

## Baselines Endpoints

### GET /api/baselines/
List all available baselines.

**Response:**
```json
{
  "available": 4,
  "baselines": {
    "bandwidth": {
      "mean": 9500.0,
      "median": 9200.0,
      "min": 1000.0,
      "max": 20000.0,
      "p95": 15000.0,
      "p99": 18000.0
    },
    "latency": {
      "mean": 45.2,
      "median": 42.5,
      "min": 5.0,
      "max": 250.0,
      "p95": 100.0,
      "p99": 150.0
    },
    "protocol": {...},
    "connection": {...}
  },
  "timestamp": "2026-01-09T17:41:06.493726"
}
```

---

### GET /api/baselines/:type
Get a specific baseline by type.

**Path Parameters:**
- `type`: `bandwidth`, `latency`, `protocol`, or `connection`

**Response:**
```json
{
  "type": "bandwidth",
  "baseline": {
    "mean": 9500.0,
    "median": 9200.0,
    "min": 1000.0,
    "max": 20000.0,
    "p95": 15000.0,
    "p99": 18000.0
  },
  "timestamp": "2026-01-09T17:41:06.493726"
}
```

**Error (404):**
```json
{
  "error": "Baseline not found",
  "type": "bandwidth"
}
```

---

### GET /api/baselines/stats
Get key statistics from all baselines.

**Response:**
```json
{
  "baseline_stats": {
    "bandwidth": {
      "mean_bps": 9500.0,
      "median_bps": 9200.0,
      "max_bps": 20000.0,
      "min_bps": 1000.0,
      "p95_bps": 15000.0
    },
    "latency": {
      "mean_rtt": 45.2,
      "median_rtt": 42.5,
      "p95_rtt": 100.0,
      "p99_rtt": 150.0
    },
    "protocol": {
      "distribution": {...}
    },
    "connection": {
      "mean_connections": 42.0,
      "median_connections": 40.0
    }
  },
  "timestamp": "2026-01-09T17:41:06.493726"
}
```

---

### POST /api/baselines/generate
Trigger baseline generation from metrics.

**Request Body:**
```json
{
  "force": false,
  "types": ["bandwidth", "latency", "protocol", "connection"]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Baselines generated successfully",
  "baselines_dir": "app/baselines",
  "generated": {
    "bandwidth": true,
    "latency": true,
    "protocol": true,
    "connection": true
  },
  "generation_time": 0.85,
  "timestamp": "2026-01-09T17:44:28.789012"
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "Metrics not found. Run /api/metrics/compute first."
}
```

---

## Control Endpoints

### POST /api/control/capture/start
Start live packet capture (requires live mode).

**Request Body:**
```json
{
  "interface": "eth0",
  "output_file": "logs/live_capture.jsonl",
  "duration": 300
}
```

**Response:**
```json
{
  "success": true,
  "message": "Live capture started on eth0",
  "interface": "eth0",
  "output_file": "logs/live_capture.jsonl",
  "start_time": "2026-01-09T17:44:30.123456",
  "duration": 300
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "Cannot start live capture in pcap mode. Start API with --mode live"
}
```

---

### POST /api/control/capture/stop
Stop live packet capture.

**Response:**
```json
{
  "success": true,
  "message": "Live capture stopped",
  "duration": 45.3,
  "output_file": "logs/live_capture.jsonl"
}
```

**Error (400):**
```json
{
  "success": false,
  "error": "No capture currently running"
}
```

---

### GET /api/control/capture/status
Get current live capture status.

**Response (Running):**
```json
{
  "running": true,
  "start_time": "2026-01-09T17:44:30.123456",
  "duration": 15.5,
  "interface": "eth0",
  "output_file": "logs/live_capture.jsonl"
}
```

**Response (Not Running):**
```json
{
  "running": false,
  "message": "No active capture"
}
```

---

### GET /api/control/logs
Get recent log entries.

**Query Parameters:**
- `type` (str, default='app'): `app` or `analysis`
- `limit` (int, default=100): Number of recent lines to return

**Response:**
```json
{
  "log_file": "logs/app.log",
  "limit": 100,
  "total_lines": 1250,
  "returned_lines": 100,
  "logs": [
    "2026-01-09 17:40:02 [INFO] API server started",
    "2026-01-09 17:40:05 [INFO] Metrics computed: 25 windows",
    ...
  ]
}
```

---

## Error Handling

All endpoints follow standard HTTP status codes:

- **200 OK**: Request successful
- **308 PERMANENT REDIRECT**: Missing trailing slash (auto-redirected)
- **400 Bad Request**: Invalid parameters or missing data
- **404 Not Found**: Resource not found
- **500 Internal Server Error**: Server error

### Error Response Format

```json
{
  "error": "Error type",
  "message": "Detailed error message",
  "timestamp": "2026-01-09T17:44:30.123456"
}
```

---

## Data Flow

### Development Workflow (PCAP File)

```
1. Start API server:
   python3 api/api_server.py --mode pcap --pcap test.pcapng

2. Compute metrics:
   POST /api/metrics/compute → logs/metrics.jsonl

3. Generate baselines (optional):
   POST /api/baselines/generate → app/baselines/*.json

4. Run anomaly detection:
   POST /api/anomalies/detect → logs/anomalies.jsonl

5. Query results:
   GET /api/metrics/ → all windows
   GET /api/anomalies/ → all anomalies
   GET /api/baselines/ → baseline profiles
```

### Production Workflow (Live Capture)

```
1. Start API server:
   sudo python3 api/api_server.py --mode live --interface eth0

2. Start live capture:
   POST /api/control/capture/start {interface: "eth0"}

3. Monitor capture status:
   GET /api/control/capture/status (while running)

4. Stop capture:
   POST /api/control/capture/stop

5. Analyze captured data:
   POST /api/metrics/compute (analyze logs/live_capture.jsonl)
   POST /api/anomalies/detect
```

---

## Examples

### Example 1: Complete PCAP Analysis

```bash
# Start server
PYTHONPATH=. python3 api/api_server.py --mode pcap --pcap data/raw/pcapng/test.pcapng &

# Compute metrics
curl -X POST http://127.0.0.1:5000/api/metrics/compute

# Generate baselines
curl -X POST http://127.0.0.1:5000/api/baselines/generate

# Run anomaly detection
curl -X POST http://127.0.0.1:5000/api/anomalies/detect

# Get summary
curl http://127.0.0.1:5000/api/metrics/summary

# Get anomalies by severity
curl "http://127.0.0.1:5000/api/anomalies/?severity=high"

# Get top anomalies
curl http://127.0.0.1:5000/api/anomalies/top?limit=5
```

### Example 2: Filtered Anomaly Query

```bash
# Get high-severity packet loss anomalies
curl "http://127.0.0.1:5000/api/anomalies/?type=packet_loss&severity=high"

# Get anomalies for window 5
curl http://127.0.0.1:5000/api/anomalies/window/5

# Get anomaly breakdown by type
curl http://127.0.0.1:5000/api/anomalies/by-type
```

### Example 3: Baseline Management

```bash
# List all baselines
curl http://127.0.0.1:5000/api/baselines/

# Get bandwidth baseline
curl http://127.0.0.1:5000/api/baselines/bandwidth

# Get latency baseline stats
curl http://127.0.0.1:5000/api/baselines/stats

# Regenerate baselines
curl -X POST http://127.0.0.1:5000/api/baselines/generate -d '{"force": true}' -H "Content-Type: application/json"
```

---

## Performance Notes

- **Metrics computation**: ~2-5 seconds per 100K packets
- **Anomaly detection**: ~1-3 seconds per 25 metric windows
- **Baseline generation**: ~0.5-1 second
- **Live capture latency**: <100ms per 10-second window

---

## Future Enhancements

- [ ] WebSocket support for real-time streaming
- [ ] Pagination for large datasets
- [ ] Advanced filtering and search
- [ ] Export to CSV/Parquet
- [ ] Dashboard integration (Grafana)
- [ ] Alert integrations (Slack, PagerDuty)
- [ ] Time-series database export (InfluxDB, Prometheus)
