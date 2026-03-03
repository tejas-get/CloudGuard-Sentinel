from models import get_all_anomalies, get_all_alerts, get_all_logs
from collections import Counter

def get_risk_summary():
    anomalies = get_all_anomalies()
    risk_counts = Counter(a['risk_level'] for a in anomalies)
    return {
        'total': len(anomalies),
        'HIGH': risk_counts.get('HIGH', 0),
        'MEDIUM': risk_counts.get('MEDIUM', 0),
        'LOW': risk_counts.get('LOW', 0),
    }

def get_dashboard_stats():
    logs = get_all_logs(limit=500)
    anomalies = get_all_anomalies(limit=500)
    alerts = get_all_alerts(limit=100)
    risk = get_risk_summary()

    # Device breakdown
    device_counts = Counter(l.get('device_type', 'unknown') for l in logs)

    # Hourly distribution
    hourly = Counter(l.get('hour_of_day', 0) for l in logs)
    hourly_list = [hourly.get(h, 0) for h in range(24)]

    return {
        'total_logs': len(logs),
        'total_anomalies': len(anomalies),
        'total_alerts': len(alerts),
        'risk_summary': risk,
        'device_counts': dict(device_counts),
        'hourly_distribution': hourly_list,
        'recent_anomalies': anomalies[:10],
        'recent_alerts': alerts[:5],
    }
