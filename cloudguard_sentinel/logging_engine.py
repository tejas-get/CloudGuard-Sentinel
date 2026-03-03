from datetime import datetime
from models import get_db

def classify_device(user_agent: str) -> str:
    ua = user_agent.lower()
    if any(k in ua for k in ['mobile', 'android', 'iphone', 'ipad']):
        return 'mobile'
    elif any(k in ua for k in ['tablet']):
        return 'tablet'
    elif any(k in ua for k in ['curl', 'python', 'bot', 'spider']):
        return 'api_client'
    return 'desktop'

def is_off_hours(hour: int) -> int:
    return 1 if (hour < 6 or hour > 22) else 0

def get_geo_location(ip: str) -> dict:
    """Look up country, city, region from IP using free ip-api.com.
    Falls back to 'Unknown' gracefully if lookup fails or times out."""
    if not ip or ip in ('127.0.0.1', '::1') or ip.startswith('192.168.') or ip.startswith('10.'):
        return {'country': 'Local', 'city': 'Localhost', 'region': 'N/A'}
    try:
        import urllib.request, json as _json
        url = f'http://ip-api.com/json/{ip}?fields=country,city,regionName,status'
        with urllib.request.urlopen(url, timeout=3) as r:
            data = _json.loads(r.read().decode())
        if data.get('status') == 'success':
            return {
                'country': data.get('country', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'region': data.get('regionName', 'Unknown'),
            }
    except Exception:
        pass
    return {'country': 'Unknown', 'city': 'Unknown', 'region': 'Unknown'}

def log_access(user_id, username, role, ip_address, user_agent, endpoint, method='GET', status_code=200):
    now = datetime.utcnow()
    hour = now.hour
    dow = now.weekday()
    device = classify_device(user_agent or '')
    off_hours = is_off_hours(hour)
    geo = get_geo_location(ip_address or '127.0.0.1')

    conn = get_db()
    cursor = conn.execute(
        '''INSERT INTO access_logs
           (user_id, username, role, timestamp, ip_address, user_agent,
            endpoint, method, status_code, hour_of_day, day_of_week,
            is_off_hours, device_type, country, city, region)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
        (user_id, username, role, now.isoformat(), ip_address, user_agent,
         endpoint, method, status_code, hour, dow, off_hours, device,
         geo['country'], geo['city'], geo['region'])
    )
    log_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return log_id
