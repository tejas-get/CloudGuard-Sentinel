// CloudGuard Sentinel — Global utilities
'use strict';

// Auto-refresh dashboard stats every 30 seconds
function autoRefresh(intervalMs = 30000) {
  setInterval(() => {
    const badge = document.querySelector('.alert-badge');
    fetch('/api/alerts')
      .then(r => r.json())
      .then(data => {
        if (badge && data.length > 0) {
          badge.textContent = `⚠ ${data.length} ACTIVE ALERT${data.length !== 1 ? 'S' : ''}`;
          badge.style.display = '';
        } else if (badge && data.length === 0) {
          badge.style.display = 'none';
        }
      })
      .catch(() => {});
  }, intervalMs);
}

document.addEventListener('DOMContentLoaded', () => {
  if (document.querySelector('.topbar')) {
    autoRefresh();
  }
});
