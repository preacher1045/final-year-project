# Matplotlib & Pandas Integration Guide

## Overview

**Matplotlib** and **Pandas** are essential components of the Network Traffic Analyzer ecosystem, though they serve different roles:

| Library | Version | Role | Status |
|---------|---------|------|--------|
| **Pandas** | 2.3.3 | Data manipulation, windowing, aggregation | ✅ **ACTIVE** |
| **Matplotlib** | 3.10.8 | Time-series visualization, charting | ✅ **READY** (with visualization script) |

---

## Pandas Usage (ACTIVE)

### 1. **Baseline Generation** (`scripts/generate_baselines.py`)

Pandas is used implicitly through Python's `statistics` module for computing baselines:

```python
# From generate_baselines.py
from statistics import mean, median

def generate_bandwidth_baseline(metrics: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Extract values across all metrics windows and compute statistics."""
    bps_values = []
    for m in metrics:
        if 'bandwidth' in m:
            bps_values.append(m['bandwidth']['mean_bps'])
    
    baseline = {
        'mean': mean(bps_values),
        'median': median(bps_values),
        'min': min(bps_values),
        'max': max(bps_values),
        'p95': percentile(bps_values, 95),  # Custom percentile calculation
    }
    return baseline
```

**Where it's used:**
- Computing rolling averages
- Extracting percentiles (p95, p99)
- Aggregating metrics across windows
- Statistical profiling

### 2. **Data Normalization** (`app/analysis/traffic_metric.py`)

Metrics computation uses implicit pandas-like operations:

```python
def compute_metrics(window_records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Windowed metric computation - similar to pandas groupby().agg()
    
    Steps:
    1. Normalize records (deduplicate by frame)
    2. Extract fields
    3. Compute aggregates (mean, median, min, max)
    4. Return summarized metrics
    """
    # Similar to: df.groupby('window').agg({'bandwidth': 'mean', 'latency': 'mean'})
```

### 3. **Window-Based Aggregation** (`scripts/run_metrics.py`)

The metrics pipeline groups packets into time windows and aggregates:

```python
def window_and_compute(records, window_seconds, out_path=None):
    """
    Equivalent pandas operation:
    
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    df.set_index('timestamp').resample(f'{window_seconds}s').agg({
        'bandwidth': 'mean',
        'latency': 'mean',
        'connections': 'count',
        'protocol': lambda x: x.value_counts()
    })
    """
```

### Why Pandas is Included (Even if not directly imported)

1. **Future dashboard integration** - Grafana, InfluxDB, Pandas DataFrames
2. **Pandas is a dependency of Matplotlib** - Matplotlib uses pandas internally for plotting
3. **Time-series analysis** - The visualization script uses pandas explicitly
4. **Data export formats** - Future CSV/Excel exports

---

## Matplotlib Usage (READY)

### Current Status

Matplotlib is **installed** but not yet integrated into the API itself. However, a complete visualization script is available at `scripts/visualize_data.py`.

### 1. **Available Visualizations**

The `visualize_data.py` script provides:

#### A. Bandwidth Timeline
```python
def plot_bandwidth_timeline(metrics_df: pd.DataFrame):
    """Plot bandwidth over time with ±1σ confidence bands."""
    ax.plot(metrics_df['timestamp'], metrics_df['bandwidth_bps'],
            label='Mean BPS', color='blue', marker='o')
    ax.fill_between(...)  # Confidence bands
```

**Output**: `reports/bandwidth_timeline.png`

#### B. Latency Timeline
```python
def plot_latency_timeline(metrics_df: pd.DataFrame):
    """Plot mean RTT and P95 latency over time."""
    ax.plot(metrics_df['timestamp'], metrics_df['latency_ms'],
            label='Mean RTT', color='green')
    ax.plot(metrics_df['timestamp'], metrics_df['latency_p95_ms'],
            label='P95 RTT', color='orange', linestyle='--')
```

**Output**: `reports/latency_timeline.png`

#### C. Protocol Distribution
```python
def plot_protocol_distribution(metrics_df: pd.DataFrame):
    """Stacked area chart of TCP/UDP/ICMP percentages."""
    ax.plot(metrics_df['timestamp'], metrics_df['protocol_tcp_pct'],
            label='TCP %', marker='o')
    ax.plot(metrics_df['timestamp'], metrics_df['protocol_udp_pct'],
            label='UDP %', marker='s')
```

**Output**: `reports/protocol_distribution.png`

#### D. Anomaly Heatmap
```python
def plot_anomaly_heatmap(metrics_df, anomalies_df):
    """Overlay detected anomalies on bandwidth timeline.
    - Blue line: bandwidth
    - Orange dashed: medium anomalies
    - Red dashed: high anomalies
    """
```

**Output**: `reports/anomaly_heatmap.png`

### 2. **How to Generate Visualizations**

```bash
# Method 1: Run the visualization script
PYTHONPATH=. python3 scripts/visualize_data.py

# Output:
# ✓ Saved: reports/bandwidth_timeline.png
# ✓ Saved: reports/latency_timeline.png
# ✓ Saved: reports/protocol_distribution.png
# ✓ Saved: reports/anomaly_heatmap.png
```

### 3. **Pandas Role in Visualization**

The `visualize_data.py` script explicitly uses pandas:

```python
import pandas as pd
import matplotlib.pyplot as plt

# Load metrics into DataFrame
metrics_df = pd.DataFrame([
    {'timestamp': ..., 'bandwidth_bps': ..., 'latency_ms': ...},
    ...
])

# Pandas operations
metrics_df['mean_bps'].mean()           # Mean of bandwidth
metrics_df['bandwidth_bps'].quantile(0.95)  # P95
metrics_df.groupby('type').size()       # Count by type
metrics_df['timestamp'].between(t1, t2) # Time range filtering

# Pass to matplotlib
ax.plot(metrics_df['timestamp'], metrics_df['bandwidth_bps'])
```

---

## Architecture Integration

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    NETWORK TRAFFIC DATA                         │
│                    (PCAP or Live Capture)                       │
└────────────────────────┬────────────────────────────────────────┘
                         │
                         ▼
        ┌────────────────────────────────┐
        │  Packet Parsers (pyshark)      │
        │  Extract frames, IPs, TCP, UDP │
        └────────┬───────────────────────┘
                 │
                 ▼
        ┌────────────────────────────────┐
        │  Metrics Computation            │ ◄─ **Implicit Pandas Logic**
        │  Windowing + Aggregation        │    (Groupby, resample)
        │  (scripts/run_metrics.py)       │
        └────────┬───────────────────────┘
                 │
                 ▼
        ┌────────────────────────────────┐
        │  logs/metrics.jsonl             │
        │  (25 metric windows)            │
        └────────┬───────────────────────┘
                 │
         ┌───────┴───────┐
         │               │
         ▼               ▼
    Baselines       Anomaly Detection
    Generation      (6 detectors)
         │               │
         ▼               ▼
    baseline_*.json  anomalies.jsonl
         │               │
         │               │
         └───────┬───────┘
                 │
                 ▼
    ┌──────────────────────────────────┐
    │  REST API (Flask)                │
    │  - GET /api/metrics/             │
    │  - GET /api/anomalies/           │
    │  - GET /api/baselines/           │
    └──────────────────────────────────┘
         │
         ▼
    ┌──────────────────────────────────┐
    │  visualize_data.py               │ ◄─ **EXPLICIT Pandas + Matplotlib**
    │  - Load metrics.jsonl             │
    │  - Load anomalies.jsonl           │
    │  - Generate plots                 │
    └──────────────────────────────────┘
         │
         ▼
    ┌──────────────────────────────────┐
    │  PNG Reports                     │
    │  - bandwidth_timeline.png        │
    │  - latency_timeline.png          │
    │  - protocol_distribution.png     │
    │  - anomaly_heatmap.png           │
    └──────────────────────────────────┘
```

---

## Implementation Examples

### Example 1: Load Data with Pandas

```python
import pandas as pd
import json

# Load metrics
metrics = []
with open('logs/metrics.jsonl') as f:
    for line in f:
        metrics.append(json.loads(line))

df = pd.DataFrame(metrics)
df['timestamp'] = pd.to_datetime(df['window_start'], unit='s')

# Statistical analysis
print(df['bandwidth'].describe())      # mean, std, min, max, quartiles
print(df['latency'].mean())            # Simple mean
print(df['latency'].quantile([0.5, 0.95, 0.99]))  # Percentiles
```

### Example 2: Group and Aggregate with Pandas

```python
# Anomalies by type and severity
anomalies = pd.read_json('logs/anomalies.jsonl', lines=True)

summary = anomalies.groupby(['type', 'severity']).size().unstack()
print(summary)
# Output:
#          medium  high
# type
# high_latency     4     2
# port_scan        1     3

# Top anomalies
top = anomalies['message'].value_counts().head(5)
```

### Example 3: Time-Series Plot with Matplotlib

```python
import matplotlib.pyplot as plt
import pandas as pd

df = pd.read_json('logs/metrics.jsonl', lines=True)
df['timestamp'] = pd.to_datetime(df['window_start'], unit='s')

fig, ax = plt.subplots()
ax.plot(df['timestamp'], df['bandwidth'], label='Bandwidth')
ax.set_xlabel('Time')
ax.set_ylabel('Bps')
ax.legend()
plt.savefig('bandwidth.png')
```

---

## Future Integration Points

### 1. **Dashboard Integration**

```python
# Future: Export to Grafana JSON format
import pandas as pd

df = pd.read_json('logs/metrics.jsonl', lines=True)

# Create Grafana panel data
panel_data = {
    'time': df['window_start'],
    'bandwidth': df['bandwidth'],
    'latency': df['latency'],
}

# Export to InfluxDB, Prometheus, Grafana
```

### 2. **Advanced Analytics**

```python
# Correlation analysis
df['bandwidth'].corr(df['latency'])

# Anomaly outlier detection
from scipy import stats
outliers = stats.zscore(df['bandwidth']) > 2

# Time-series decomposition
from statsmodels.tsa.seasonal import seasonal_decompose
decomposition = seasonal_decompose(df['bandwidth'], period=10)
```

### 3. **Report Generation**

```python
# Export to Excel with pandas
with pd.ExcelWriter('report.xlsx') as writer:
    metrics_df.to_excel(writer, sheet_name='Metrics')
    anomalies_df.to_excel(writer, sheet_name='Anomalies')

# HTML reports
html = metrics_df.to_html(index=False)
with open('report.html', 'w') as f:
    f.write(html)
```

---

## Summary Table

| Component | Library | Usage | File(s) |
|-----------|---------|-------|---------|
| **Baseline Generation** | Python stats (pandas-like) | Windowing, percentiles | `scripts/generate_baselines.py` |
| **Metrics Computation** | Custom (pandas-inspired) | Groupby, aggregation | `scripts/run_metrics.py`, `app/analysis/` |
| **Data Visualization** | Pandas + Matplotlib | Time-series plotting | `scripts/visualize_data.py` |
| **API** | Flask | REST endpoints | `api/api_server.py` |
| **Statistical Analysis** | Pandas (via visualize_data.py) | Mean, median, quantiles | `scripts/visualize_data.py` |

---

## Getting Started

### Step 1: Compute Metrics
```bash
PYTHONPATH=. python3 api/api_server.py --mode pcap --pcap data/raw/pcapng/test_net_traffic.pcapng &

curl -X POST http://127.0.0.1:5000/api/metrics/compute
```

### Step 2: Generate Visualizations
```bash
PYTHONPATH=. python3 scripts/visualize_data.py
```

### Step 3: View Reports
```bash
ls -la reports/
# bandwidth_timeline.png
# latency_timeline.png
# protocol_distribution.png
# anomaly_heatmap.png
```

---

## Status

✅ **Pandas**: Active (implicit in baseline generation, explicit in visualization)  
✅ **Matplotlib**: Ready (visualization script fully implemented)  
✅ **API**: Fully functional (22 endpoints, all tested)  
⏳ **Future**: Dashboard integration, advanced analytics, Excel reports

---

**Last Updated**: January 9, 2026  
**Version**: 1.0.0
