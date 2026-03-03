import json
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from models import get_db, get_all_logs, mark_user_suspicious
from feature_engineering import extract_features

FEATURE_COLS = ['hour_of_day', 'day_of_week', 'device_encoded', 'role_encoded', 'is_off_hours', 'rapid_access']

# Add your expected countries here — logins from other countries will be flagged
TRUSTED_COUNTRIES = ['India', 'United States', 'United Kingdom', 'Canada', 'Australia']

_model = None
_scaler = None

def train_model():
    global _model, _scaler
    logs = get_all_logs(limit=500)
    df = extract_features(logs)
    if df.empty or len(df) < 5:
        return False
    X = df[FEATURE_COLS].values
    _scaler = StandardScaler()
    X_scaled = _scaler.fit_transform(X)
    _model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)
    _model.fit(X_scaled)
    return True

def get_isolation_score(feature_row: dict) -> float:
    global _model, _scaler
    if _model is None or _scaler is None:
        success = train_model()
        if not success:
            return 0.0
    try:
        X = np.array([[feature_row.get(c, 0) for c in FEATURE_COLS]])
        X_scaled = _scaler.transform(X)
        score = _model.decision_function(X_scaled)[0]
        normalized = float(np.clip((score + 0.5) / 1.0, 0, 1))
        return normalized
    except Exception:
        return 0.5

def apply_rules(log: dict) -> list:
    flags = []
    if log.get('is_off_hours') == 1:
        flags.append('OFF_HOURS_ACCESS')
    if log.get('role') == 'admin' and log.get('endpoint', '').startswith('/admin'):
        if log.get('hour_of_day', 12) < 6 or log.get('hour_of_day', 12) > 22:
            flags.append('ADMIN_OFF_HOURS')
    if log.get('rapid_access', 1) > 10:
        flags.append('RAPID_ACCESS_DETECTED')
    if log.get('device_type') == 'api_client':
        flags.append('API_CLIENT_ACCESS')
    # GeoIP anomaly: flag if country is not Local/Unknown and looks unusual
    country = log.get('country', 'Unknown')
    if country not in ('Local', 'Unknown', None, '') and country not in TRUSTED_COUNTRIES:
        flags.append(f'UNUSUAL_LOCATION:{country}')
    return flags

def compute_risk_level(isolation_score: float, rule_flags: list) -> str:
    rule_weight = len(rule_flags) * 0.2
    combined = (1 - isolation_score) + rule_weight
    if combined >= 0.6:
        return 'HIGH'
    elif combined >= 0.3:
        return 'MEDIUM'
    return 'LOW'

def analyze_log(log_id: int, log: dict, feature_row: dict):
    iso_score = get_isolation_score(feature_row)
    flags = apply_rules(log)
    risk = compute_risk_level(iso_score, flags)

    details = {
        'isolation_score': round(iso_score, 4),
        'rule_flags': flags,
        'risk_level': risk
    }

    conn = get_db()
    conn.execute(
        '''INSERT INTO anomaly_scores
           (log_id, username, timestamp, isolation_score, rule_flags, risk_level, details)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (log_id, log.get('username'), log.get('timestamp'),
         iso_score, json.dumps(flags), risk, json.dumps(details))
    )
    conn.commit()
    conn.close()

    if risk == 'HIGH':
        trigger_alert(log.get('username', 'unknown'), risk, flags)
        mark_user_suspicious(log.get('username', ''))

    return risk, flags, iso_score

def trigger_alert(username: str, risk_level: str, flags: list):
    from datetime import datetime
    conn = get_db()
    message = f"High-risk access detected for user '{username}'. Flags: {', '.join(flags)}"
    conn.execute(
        'INSERT INTO alerts (username, timestamp, risk_level, message) VALUES (?, ?, ?, ?)',
        (username, datetime.utcnow().isoformat(), risk_level, message)
    )
    conn.commit()
    conn.close()

    # Email alert — optional, never crashes the app if not configured
    try:
        from flask_mail import Message
        from app import mail, app as flask_app
        with flask_app.app_context():
            msg = Message(
                subject="⚠️ CloudGuard Sentinel — HIGH Risk Alert",
                recipients=["admin@yourdomain.com"],
                body=f"HIGH risk access detected for user '{username}'.\nFlags: {', '.join(flags)}\nTimestamp: {datetime.utcnow().isoformat()}"
            )
            mail.send(msg)
        print(f"[Email] Alert sent for user '{username}'")
    except Exception as e:
        print(f"[Email Skipped] {e}")

def retrain():
    global _model, _scaler
    _model = None
    _scaler = None
    return train_model()
