# ids_ml_system/config.py
"""Configuration globale du système"""

# Stockage global pour les logs
from collections import deque

console_logs = deque(maxlen=500)
traffic_logs = deque(maxlen=200)
alert_logs = deque(maxlen=200)
insecure_sites_logs = deque(maxlen=200)

# Configuration
CONFIG = {
    'ML_CONFIDENCE_THRESHOLD': 0.85,
    'ALERT_DEDUPLICATION_WINDOW': 300,
    'MAX_ALERTS_PER_MINUTE': 10,
    'WHITELIST_PROCESSES': [
        'svchost.exe', 'System', 'Registry', 'MsMpEng.exe'
    ],
    'SUSPICIOUS_PORTS': [135, 139, 445, 3389, 22, 23, 21, 25, 110, 143]
}