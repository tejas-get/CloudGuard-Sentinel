from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, make_response
from functools import wraps
import json, csv, io
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'cloudguard-sentinel-secret-2024-xK9mP2qR'

# ─── Optional Email Config ─────────────────────────────────────────────────────
# To enable email alerts:
# 1. Set your Gmail address below
# 2. Generate a Gmail App Password at: myaccount.google.com/apppasswords
# 3. Paste the 16-character app password (no spaces)
# Leave as-is to run without email (alerts still show in dashboard)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = ''   # e.g. 'yourname@gmail.com'
app.config['MAIL_PASSWORD'] = ''   # e.g. 'abcdefghijklmnop'
app.config['MAIL_DEFAULT_SENDER'] = ''

try:
    from flask_mail import Mail
    mail = Mail(app)
except Exception:
    mail = None

from models import init_db, get_all_users, get_all_logs, get_all_anomalies, get_all_alerts, \
    delete_user, get_user_by_id, get_unacknowledged_alerts, acknowledge_alert, get_logs_for_user
from auth import authenticate_user, register_user, seed_default_users
from logging_engine import log_access
from feature_engineering import extract_features
from hybrid_detection import analyze_log, retrain
from risk_scoring import get_dashboard_stats

# ─── Init ─────────────────────────────────────────────────────────────────────
with app.app_context():
    init_db()
    seed_default_users()

# ─── Auth Decorators ──────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return render_template('user_dashboard.html', error="Access denied."), 403
        return f(*args, **kwargs)
    return decorated

# ─── Logging Middleware ───────────────────────────────────────────────────────
def log_and_analyze():
    if 'user_id' not in session:
        return
    user_id = session['user_id']
    username = session['username']
    role = session['role']
    ip = request.remote_addr or '127.0.0.1'
    ua = request.user_agent.string
    endpoint = request.path
    method = request.method

    log_id = log_access(user_id, username, role, ip, ua, endpoint, method)

    from models import get_db
    conn = get_db()
    log_row = conn.execute('SELECT * FROM access_logs WHERE id = ?', (log_id,)).fetchone()
    conn.close()
    if log_row:
        log_dict = dict(log_row)
        recent = get_all_logs(limit=50)
        user_recent = [l for l in recent if l['username'] == username]
        log_dict['rapid_access'] = len(user_recent)
        feature_row = {
            'hour_of_day': log_dict.get('hour_of_day', 12),
            'day_of_week': log_dict.get('day_of_week', 0),
            'device_encoded': {'desktop': 0, 'mobile': 1, 'tablet': 2, 'api_client': 3}.get(log_dict.get('device_type', 'desktop'), 0),
            'role_encoded': 1 if role == 'admin' else 0,
            'is_off_hours': log_dict.get('is_off_hours', 0),
            'rapid_access': log_dict.get('rapid_access', 1),
        }
        analyze_log(log_id, log_dict, feature_row)

# ─── Routes ───────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user, msg = authenticate_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            log_and_analyze()
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        return render_template('login.html', error=msg)
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    log_and_analyze()
    stats = get_dashboard_stats()
    users = get_all_users()
    alerts = get_unacknowledged_alerts()
    return render_template('admin_dashboard.html',
                           stats=stats, users=users, alerts=alerts,
                           username=session['username'])

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    log_and_analyze()
    logs = get_logs_for_user(session['username'], limit=20)
    anomalies = get_all_anomalies(limit=200)
    user_anomalies = [a for a in anomalies if a.get('username') == session['username']][:10]
    return render_template('user_dashboard.html',
                           username=session['username'],
                           role=session['role'],
                           logs=logs,
                           anomalies=user_anomalies)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def remove_user(user_id):
    delete_user(user_id)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/register', methods=['POST'])
@admin_required
def admin_register():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    role = request.form.get('role', 'user')
    ok, msg = register_user(username, password, role)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/alerts/acknowledge/<int:alert_id>', methods=['POST'])
@admin_required
def ack_alert(alert_id):
    acknowledge_alert(alert_id)
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/retrain', methods=['POST'])
@admin_required
def retrain_model():
    success = retrain()
    return jsonify({'success': success})

# ─── CSV Export ───────────────────────────────────────────────────────────────
@app.route('/admin/export/logs')
@admin_required
def export_logs():
    logs = get_all_logs(limit=10000)
    if not logs:
        return "No logs to export.", 404
    si = io.StringIO()
    writer = csv.DictWriter(si, fieldnames=logs[0].keys())
    writer.writeheader()
    writer.writerows(logs)
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=access_logs.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/admin/export/anomalies')
@admin_required
def export_anomalies():
    data = get_all_anomalies(limit=10000)
    if not data:
        return "No anomalies to export.", 404
    si = io.StringIO()
    writer = csv.DictWriter(si, fieldnames=data[0].keys())
    writer.writeheader()
    writer.writerows(data)
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = "attachment; filename=anomalies.csv"
    output.headers["Content-type"] = "text/csv"
    return output

# ─── API Endpoints ────────────────────────────────────────────────────────────
@app.route('/api/stats')
@admin_required
def api_stats():
    stats = get_dashboard_stats()
    return jsonify(stats)

@app.route('/api/anomalies')
@admin_required
def api_anomalies():
    data = get_all_anomalies(limit=100)
    return jsonify(data)

@app.route('/api/logs')
@admin_required
def api_logs():
    data = get_all_logs(limit=200)
    return jsonify(data)

@app.route('/api/alerts')
@admin_required
def api_alerts_unread():
    data = get_unacknowledged_alerts()
    return jsonify(data)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
