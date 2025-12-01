# ids_ml_system/preprocessor.py
"""Préprocessing des données pour le ML"""
import numpy as np
from datetime import datetime
from sklearn.preprocessing import StandardScaler, LabelEncoder
from .logger import Logger
from .config import CONFIG

class MLDataPreprocessor:
    def __init__(self):
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_names = [
            'packet_size', 'protocol', 'src_port', 'dst_port', 'ttl',
            'hour', 'minute', 'src_ip_encoded', 'dst_ip_encoded',
            'is_common_port', 'is_private_ip', 'packet_size_std',
            'is_whitelisted_process', 'is_suspicious_port'
        ]
        Logger.add_console_log("✅ Preprocesseur ML initialisé")
    
    def prepare_features(self, packet_data):
        """Prépare les features pour le modèle ML"""
        try:
            packet_size = packet_data.get('packet_size', 0)
            protocol = packet_data.get('protocol', 0)
            src_port = packet_data.get('src_port', 0)
            dst_port = packet_data.get('dst_port', 0)
            ttl = packet_data.get('ttl', 64)
            
            now = datetime.now()
            hour = now.hour
            minute = now.minute
            
            src_ip_encoded = self.encode_ip(packet_data.get('src_ip', '0.0.0.0'))
            dst_ip_encoded = self.encode_ip(packet_data.get('dst_ip', '0.0.0.0'))
            
            is_common_port = 1 if dst_port in [80, 443, 53, 22, 21, 25, 110, 143] else 0
            is_private_ip = 1 if self.is_private_ip(packet_data.get('src_ip', '')) else 0
            packet_size_std = abs(packet_size - 1000) / 500
            
            process_name = packet_data.get('process', '').lower()
            is_whitelisted_process = 1 if any(
                whitelist.lower() in process_name for whitelist in CONFIG['WHITELIST_PROCESSES']
            ) else 0
            is_suspicious_port = 1 if dst_port in CONFIG['SUSPICIOUS_PORTS'] else 0
            
            features = [
                packet_size, protocol, src_port, dst_port, ttl,
                hour, minute, src_ip_encoded, dst_ip_encoded,
                is_common_port, is_private_ip, packet_size_std,
                is_whitelisted_process, is_suspicious_port
            ]
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            Logger.add_console_log(f"❌ Erreur préprocessing: {e}", "error")
            return np.array([0] * 14).reshape(1, -1)
    
    def encode_ip(self, ip_address):
        """Encode une adresse IP en valeur numérique"""
        try:
            parts = ip_address.split('.')
            if len(parts) == 4:
                return sum(int(part) * (256 ** (3-i)) for i, part in enumerate(parts)) / 1000000000.0
            return hash(ip_address) % 1000 / 1000.0
        except:
            return 0.5
    
    def is_private_ip(self, ip_address):
        """Vérifie si l'IP est une IP privée"""
        try:
            parts = list(map(int, ip_address.split('.')))
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            return False
        except:
            return False
    
    def fit_scaler(self, features):
        """Entraîne le scaler sur les features"""
        try:
            self.scaler.fit(features)
            Logger.add_console_log("✅ Scaler entraîné avec succès")
        except Exception as e:
            Logger.add_console_log(f"❌ Erreur entraînement scaler: {e}", "error")