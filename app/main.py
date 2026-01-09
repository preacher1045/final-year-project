import logging
import os
import json
from typing import Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)

log_folder = "logs"
log_file = "app.log"

def setup_logging():
    """Initialize logger with file and console handlers."""
    os.makedirs(log_folder, exist_ok=True)
    log_path = os.path.join(log_folder, log_file)

    # Clear existing handlers
    logger.handlers.clear()
    logger.setLevel(logging.INFO)

    # Create formatter
    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    # File handler
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(formatter)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)


def log_anomaly_detection(
    anomaly: Dict[str, Any],
    window_num: int
) -> None:
    """
    Log a simplified anomaly detection with appropriate tags.
    
    Args:
        anomaly: Single anomaly dict from detection results
        window_num: Window number for context
    """
    anom_type = anomaly.get('type', 'unknown')
    severity = anomaly.get('severity', 'unknown').upper()
    metric = anomaly.get('metric', 'N/A')
    current_value = anomaly.get('current_value', 'N/A')
    threshold = anomaly.get('threshold', 'N/A')
    message = anomaly.get('message', 'No detail')
    
    # Build simplified log message with tags
    tag = f"[{anom_type.upper()}]"
    severity_tag = f"[{severity}]"
    window_tag = f"[W{window_num}]"
    
    log_msg = (
        f"{window_tag} {tag} {severity_tag} {message} "
        f"(current: {current_value}, threshold: {threshold})"
    )
    
    # Log with appropriate level
    if severity == 'HIGH':
        logger.error(log_msg)
    else:  # MEDIUM or other
        logger.warning(log_msg)


def log_anomaly_window_summary(
    window_num: int,
    anomalies: List[Dict[str, Any]],
    window_start: float,
    window_end: float
) -> None:
    """
    Log summary for a metric window with anomalies.
    
    Args:
        window_num: Window number
        anomalies: List of anomalies detected in this window
        window_start: Window start timestamp
        window_end: Window end timestamp
    """
    if not anomalies:
        return
    
    # Count by severity
    high_count = sum(1 for a in anomalies if a.get('severity') == 'high')
    medium_count = sum(1 for a in anomalies if a.get('severity') == 'medium')
    
    # Count by type
    by_type = {}
    for a in anomalies:
        atype = a.get('type', 'unknown')
        by_type[atype] = by_type.get(atype, 0) + 1
    
    # Build summary message
    types_str = ', '.join([f"{t}({c})" for t, c in by_type.items()])
    summary_msg = (
        f"[W{window_num}] [SUMMARY] {len(anomalies)} anomalies detected: "
        f"HIGH={high_count}, MEDIUM={medium_count} | Types: {types_str}"
    )
    
    logger.warning(summary_msg)


def log_analysis_start() -> None:
    """Log start of anomaly detection analysis."""
    logger.info("=" * 70)
    logger.info("Starting network traffic anomaly detection analysis")
    logger.info("=" * 70)


def log_analysis_complete(total_windows: int, anomalies_found: int) -> None:
    """
    Log completion of analysis with summary.
    
    Args:
        total_windows: Total metric windows processed
        anomalies_found: Total anomalies detected
    """
    anomaly_rate = round(100.0 * anomalies_found / total_windows, 2) if total_windows > 0 else 0
    
    logger.info("=" * 70)
    logger.info(f"Analysis complete: {total_windows} windows, {anomalies_found} anomalies ({anomaly_rate}%)")
    logger.info("=" * 70)


def log_detection_statistics(stats: Dict[str, Any]) -> None:
    """
    Log overall detection statistics.
    
    Args:
        stats: Statistics dict from anomaly engine
    """
    logger.info("[STATS] Detection Summary:")
    logger.info(f"  Windows analyzed: {stats.get('total_windows', 0)}")
    logger.info(f"  Windows with anomalies: {stats.get('windows_with_anomalies', 0)}")
    logger.info(f"  Anomaly rate: {stats.get('anomaly_percentage', 0)}%")
    logger.info(f"  Total anomalies: {stats.get('total_anomalies', 0)}")
    
    by_type = stats.get('by_type', {})
    if by_type:
        logger.info("  By type:")
        for atype, counts in by_type.items():
            logger.info(f"    {atype}: {counts['count']} (HIGH: {counts['high']}, MEDIUM: {counts['medium']})")
    
    by_severity = stats.get('by_severity', {})
    logger.info(f"  By severity: HIGH={by_severity.get('high', 0)}, MEDIUM={by_severity.get('medium', 0)}")


def analyze_and_log(metrics_jsonl: str = "logs/metrics.jsonl") -> None:
    """
    Full analysis pipeline: load metrics, detect anomalies, log results.
    
    Args:
        metrics_jsonl: Path to metrics JSONL file
    """
    from app.anomalies.anomaly_engine import AnomalyEngine
    
    setup_logging()
    log_analysis_start()
    
    # Initialize engine
    engine = AnomalyEngine()
    
    # Batch analyze
    results = engine.batch_analyze(metrics_jsonl)
    
    # Log each window's anomalies
    for window_num, result in enumerate(results, 1):
        anomalies = result.get('anomalies', [])
        
        if anomalies:
            # Log window summary
            log_anomaly_window_summary(
                window_num,
                anomalies,
                result.get('window_start'),
                result.get('window_end')
            )
            
            # Log each anomaly
            for anom in anomalies:
                log_anomaly_detection(anom, window_num)
    
    # Export results
    engine.export_detections()
    
    # Get and log statistics
    stats = engine.get_statistics()
    log_detection_statistics(stats)
    
    # Final summary
    log_analysis_complete(stats['total_windows'], stats['total_anomalies'])


def main():
    """Main entry point."""
    setup_logging()
    logger.info("Application initialized.")
    logger.info("Call analyze_and_log() to run anomaly detection with logging.")


if __name__ == "__main__":
    main()
