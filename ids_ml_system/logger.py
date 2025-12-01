# ids_ml_system/logger.py
"""Gestion centralisée des logs"""
from datetime import datetime
from .config import console_logs, traffic_logs, alert_logs, insecure_sites_logs

class Logger:
    @staticmethod
    def add_console_log(message, log_type="info"):
        """Ajoute un message aux logs de la console"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        log_entry = {
            'timestamp': timestamp,
            'message': message,
            'type': log_type
        }
        console_logs.append(log_entry)
        print(f"[{timestamp}] {message}")
    
    @staticmethod
    def add_traffic_log(traffic_data):
        """Ajoute un log de trafic"""
        traffic_logs.append(traffic_data)
    
    @staticmethod
    def add_alert_log(alert_data):
        """Ajoute une alerte"""
        alert_logs.append(alert_data)
    
    @staticmethod
    def add_insecure_site(site_data):
        """Ajoute un site non sécurisé"""
        insecure_sites_logs.append(site_data)
    
    @staticmethod
    def clear_all_logs():
        """Efface tous les logs"""
        console_logs.clear()
        traffic_logs.clear()
        alert_logs.clear()
        insecure_sites_logs.clear()