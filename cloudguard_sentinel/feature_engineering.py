import pandas as pd
import numpy as np
from models import get_all_logs

DEVICE_MAP = {'desktop': 0, 'mobile': 1, 'tablet': 2, 'api_client': 3}
ROLE_MAP = {'user': 0, 'admin': 1}

def extract_features(logs: list) -> pd.DataFrame:
    if not logs:
        return pd.DataFrame()

    df = pd.DataFrame(logs)
    df['device_encoded'] = df['device_type'].map(DEVICE_MAP).fillna(0).astype(int)
    df['role_encoded'] = df['role'].map(ROLE_MAP).fillna(0).astype(int)
    df['hour_of_day'] = df['hour_of_day'].fillna(12).astype(int)
    df['day_of_week'] = df['day_of_week'].fillna(0).astype(int)
    df['is_off_hours'] = df['is_off_hours'].fillna(0).astype(int)

    # Rapid login detection: count logins per user in rolling window
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df = df.sort_values('timestamp')

    # Count requests per user in last 5 minutes (simulated via row proximity)
    df['rapid_access'] = 0
    for user in df['username'].unique():
        u_idx = df[df['username'] == user].index
        user_times = df.loc[u_idx, 'timestamp']
        for i, t in zip(u_idx, user_times):
            window = user_times[(user_times >= t - pd.Timedelta(minutes=5)) & (user_times <= t)]
            df.at[i, 'rapid_access'] = len(window)

    feature_cols = ['hour_of_day', 'day_of_week', 'device_encoded',
                    'role_encoded', 'is_off_hours', 'rapid_access']
    return df[['id'] + feature_cols].copy()

def get_feature_matrix():
    logs = get_all_logs(limit=500)
    return extract_features(logs)
