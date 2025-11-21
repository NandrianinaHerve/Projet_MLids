# ids_ml_complete.py
import traceback
from flask import Flask, render_template, jsonify, request
import time
import os
import random
from datetime import datetime
import numpy as np
from collections import deque
import threading
import subprocess
import socket
import psutil
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import accuracy_score, classification_report
import pandas as pd

app = Flask(__name__)

print("🚀 SYSTÈME IDS COMPLET AVEC MACHINE LEARNING")

# Stockage global pour les logs et trafic
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
         #'msedge.exe', 'chrome.exe', 'firefox.exe', 'opera.exe', 'safari.exe',
        'svchost.exe', 'System', 'Registry', 'MsMpEng.exe'
    ],
    'SUSPICIOUS_PORTS': [135, 139, 445, 3389, 22, 23, 21, 25, 110, 143]
}

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

def add_traffic_log(traffic_data):
    """Ajoute un log de trafic"""
    traffic_logs.append(traffic_data)

def add_alert_log(alert_data):
    """Ajoute une alerte"""
    alert_logs.append(alert_data)

def add_insecure_site(site_data):
    """Ajoute un site non sécurisé"""
    insecure_sites_logs.append(site_data)

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
        add_console_log("✅ Preprocesseur ML initialisé")
    
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
            is_whitelisted_process = 1 if any(whitelist.lower() in process_name for whitelist in CONFIG['WHITELIST_PROCESSES']) else 0
            is_suspicious_port = 1 if dst_port in CONFIG['SUSPICIOUS_PORTS'] else 0
            
            features = [
                packet_size, protocol, src_port, dst_port, ttl,
                hour, minute, src_ip_encoded, dst_ip_encoded,
                is_common_port, is_private_ip, packet_size_std,
                is_whitelisted_process, is_suspicious_port
            ]
            
            return np.array(features).reshape(1, -1)
            
        except Exception as e:
            add_console_log(f"❌ Erreur préprocessing: {e}", "error")
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
            add_console_log("✅ Scaler entraîné avec succès")
        except Exception as e:
            add_console_log(f"❌ Erreur entraînement scaler: {e}", "error")

class MLTrafficClassifier:
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.accuracy = 0.0
        self.preprocessor = MLDataPreprocessor()
        add_console_log("✅ Classificateur ML initialisé")
    
    def load_model(self):
        """Charge un modèle pré-entraîné"""
        try:
            if os.path.exists('ids_ml_model.joblib'):
                model_data = joblib.load('ids_ml_model.joblib')
                self.model = model_data['model']
                self.preprocessor.scaler = model_data['scaler']
                self.accuracy = model_data['accuracy']
                self.is_trained = True
                add_console_log("📂 Modèle ML pré-entraîné chargé avec succès!", "success")
                add_console_log(f"📊 Accuracy du modèle chargé: {self.accuracy:.2%}", "success")
                return True
            else:
                add_console_log("ℹ️  Aucun modèle sauvegardé trouvé. Entraînement nécessaire.", "info")
                return False
        except Exception as e:
            add_console_log(f"❌ Erreur chargement modèle: {e}", "error")
            return False
    
    def is_legitimate_traffic(self, packet_data):
        """Vérifie si le trafic est légitime pour réduire les faux positifs"""
        dst_port = packet_data.get('dst_port', 0)
        process_name = packet_data.get('process', '').lower()
        
        # Trafic browser vers HTTPS/HTTP est normal
        browsers = ['msedge', 'chrome', 'firefox', 'opera', 'safari']
        if any(browser in process_name for browser in browsers) and dst_port in [443, 80]:
            return True
        
        # Ports communs légitimes
        common_ports = [443, 80, 53, 993, 995, 5223, 5228]
        if dst_port in common_ports:
            return True
        
        return False
    
    def generate_training_data(self, num_samples=2000):
        """Génère des données d'entraînement réalistes"""
        add_console_log("🤖 Génération des données d'entraînement...")
        
        features_list = []
        labels_list = []
        
        for i in range(num_samples):
            # 85% de trafic normal, 15% de trafic malveillant
            if random.random() < 0.85:
                # Trafic normal
                packet_size = random.randint(500, 1500)
                dst_port = random.choice([443, 80, 53, 993, 995])
                protocol = 6
                ttl = random.randint(50, 128)
                src_port = random.randint(10000, 60000)
                is_private_ip = random.choice([0, 1])
                is_whitelisted_process = random.choice([0, 1])
                is_suspicious_port = 0
                label = 0
            else:
                # Trafic malveillant
                attack_type = random.choice(['port_scan', 'ddos', 'exploit', 'suspicious'])
                if attack_type == 'port_scan':
                    packet_size = random.randint(20, 100)
                    dst_port = random.choice(CONFIG['SUSPICIOUS_PORTS'])
                    protocol = 6
                    ttl = random.randint(10, 50)
                    src_port = random.randint(10000, 60000)
                    is_private_ip = 0
                    is_whitelisted_process = 0
                    is_suspicious_port = 1
                elif attack_type == 'ddos':
                    packet_size = random.randint(10, 100)
                    dst_port = random.choice([80, 443])
                    protocol = 6
                    ttl = random.randint(200, 255)
                    src_port = random.randint(10000, 60000)
                    is_private_ip = 0
                    is_whitelisted_process = 0
                    is_suspicious_port = 0
                elif attack_type == 'exploit':
                    packet_size = random.randint(100, 1000)
                    dst_port = random.choice([135, 139, 445, 3389])
                    protocol = 6
                    ttl = random.randint(30, 60)
                    src_port = random.randint(10000, 60000)
                    is_private_ip = 0
                    is_whitelisted_process = 0
                    is_suspicious_port = 1
                else:
                    packet_size = random.randint(10, 5000)
                    dst_port = random.choice(CONFIG['SUSPICIOUS_PORTS'])
                    protocol = random.choice([6, 17])
                    ttl = random.randint(1, 255)
                    src_port = random.randint(1, 65535)
                    is_private_ip = random.choice([0, 1])
                    is_whitelisted_process = 0
                    is_suspicious_port = 1
                label = 1
            
            hour = random.randint(0, 23)
            minute = random.randint(0, 59)
            src_ip_encoded = random.random()
            dst_ip_encoded = random.random()
            is_common_port = 1 if dst_port in [80, 443, 53, 22, 21, 25] else 0
            packet_size_std = abs(packet_size - 1000) / 500
            
            features = [
                packet_size, protocol, src_port, dst_port, ttl,
                hour, minute, src_ip_encoded, dst_ip_encoded,
                is_common_port, is_private_ip, packet_size_std,
                is_whitelisted_process, is_suspicious_port
            ]
            features_list.append(features)
            labels_list.append(label)
        
        add_console_log(f"✅ Données d'entraînement générées: {len(features_list)} échantillons")
        return np.array(features_list), np.array(labels_list)
    
    def train_model(self):
        """Entraîne le modèle Random Forest"""
        try:
            add_console_log("🎯 Début de l'entraînement du modèle ML...")
            
            X, y = self.generate_training_data(2000)
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            self.preprocessor.fit_scaler(X_train)
            X_train_scaled = self.preprocessor.scaler.transform(X_train)
            X_test_scaled = self.preprocessor.scaler.transform(X_test)
            
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=20,
                min_samples_split=5,
                min_samples_leaf=2,
                random_state=42,
                n_jobs=-1
            )
            
            self.model.fit(X_train_scaled, y_train)
            y_pred = self.model.predict(X_test_scaled)
            self.accuracy = accuracy_score(y_test, y_pred)
            self.is_trained = True
            
            add_console_log(f"✅ Modèle Random Forest entraîné avec succès!", "success")
            add_console_log(f"📊 Accuracy: {self.accuracy:.2%}", "success")
            
            self.save_model()
            return self.accuracy
            
        except Exception as e:
            add_console_log(f"❌ Erreur entraînement modèle: {e}", "error")
            return 0.0
    
    def predict(self, packet_data):
        """Fait une prédiction avec le modèle ML"""
        
        # Vérifier d'abord si c'est du trafic légitime
        if self.is_legitimate_traffic(packet_data):
            return {
                'prediction': 'NORMAL', 
                'confidence': 0.95, 
                'probability_attack': 0.05,
                'reason': 'Trafic browser légitime',
                'features_used': 0
            }
        
        if not self.is_trained or self.model is None:
            return {
                'prediction': 'NORMAL', 
                'confidence': 0.5, 
                'probability_attack': 0.5,
                'reason': 'Modèle non entraîné',
                'features_used': 0
            }
        
        try:
            ml_features = self.preprocessor.prepare_features(packet_data)
            ml_features_scaled = self.preprocessor.scaler.transform(ml_features)
            prediction = self.model.predict(ml_features_scaled)[0]
            probabilities = self.model.predict_proba(ml_features_scaled)[0]
            confidence = probabilities[prediction]
            probability_attack = probabilities[1]
            prediction_label = 'ATTACK' if prediction == 1 else 'NORMAL'
            
            reason = "Trafic normal analysé" if prediction_label == 'NORMAL' else "Anomalie détectée par ML"
            
            return {
                'prediction': prediction_label,
                'confidence': float(confidence),
                'probability_attack': float(probability_attack),
                'features_used': len(ml_features[0]),
                'reason': reason
            }
            
        except Exception as e:
            add_console_log(f"❌ Erreur prédiction ML: {e}", "error")
            return {
                'prediction': 'NORMAL', 
                'confidence': 0.5, 
                'probability_attack': 0.5,
                'reason': 'Erreur prédiction',
                'features_used': 0
            }
    
    def save_model(self):
        """Sauvegarde le modèle entraîné"""
        try:
            model_data = {
                'model': self.model,
                'scaler': self.preprocessor.scaler,
                'accuracy': self.accuracy,
                'feature_names': self.preprocessor.feature_names
            }
            joblib.dump(model_data, 'ids_ml_model.joblib')
            add_console_log("💾 Modèle ML sauvegardé: ids_ml_model.joblib", "success")
        except Exception as e:
            add_console_log(f"❌ Erreur sauvegarde modèle: {e}", "error")
    
    def get_model_info(self):
        """Retourne les informations du modèle"""
        if not self.is_trained:
            return {
                'status': 'Non entraîné',
                'accuracy': 0.0,
                'features': 0,
                'algorithm': 'Aucun',
                'threshold': CONFIG['ML_CONFIDENCE_THRESHOLD']
            }
        
        return {
            'status': 'Entraîné',
            'accuracy': float(self.accuracy),
            'features': len(self.preprocessor.feature_names),
            'algorithm': 'Random Forest',
            'feature_names': self.preprocessor.feature_names,
            'threshold': CONFIG['ML_CONFIDENCE_THRESHOLD']
        }

class RealNetworkCapture:
    def __init__(self):
        self.packets = []
        self.is_capturing = False
        self.stats = {'total_packets': 0, 'packets_per_second': 0}
        self.capture_thread = None
        self.should_stop = False
        self.connections_history = set()
        add_console_log("✅ Capture réseau initialisée")
    
    def get_active_connections_detailed(self):
        """Capture les connexions réseau ACTIVES en temps réel"""
        try:
            result = subprocess.run(
                ['netstat', '-n', '-o'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                timeout=5
            )
            
            if result.returncode != 0:
                return []
            
            connections = []
            
            for line in result.stdout.split('\n'):
                if 'ESTABLISHED' in line and 'TCP' in line:
                    parts = line.strip().split()
                    if len(parts) >= 5:
                        try:
                            local_addr = parts[1]
                            remote_addr = parts[2]
                            pid = parts[4] if len(parts) > 4 else 'N/A'
                            
                            local_ip, local_port = local_addr.rsplit(':', 1)
                            remote_ip, remote_port = remote_addr.rsplit(':', 1)
                            
                            if remote_ip in ['127.0.0.1', 'localhost']:
                                continue
                            
                            conn_id = f"{local_ip}:{local_port}-{remote_ip}:{remote_port}"
                            
                            if conn_id not in self.connections_history:
                                self.connections_history.add(conn_id)
                                process_name = self.get_process_name(pid)
                                packet_size = random.randint(200, 1500)
                                ttl = random.randint(30, 255)
                                
                                connections.append({
                                    'timestamp': time.time(),
                                    'src_ip': local_ip,
                                    'dst_ip': remote_ip,
                                    'src_port': int(local_port),
                                    'dst_port': int(remote_port),
                                    'protocol': 6,
                                    'packet_size': packet_size,
                                    'ttl': ttl,
                                    'process': process_name,
                                    'pid': pid,
                                    'status': 'ESTABLISHED',
                                    'real_traffic': True,
                                    'connection_new': True
                                })
                        except (ValueError, IndexError):
                            continue
            
            return connections
            
        except Exception as e:
            add_console_log(f"❌ Erreur capture connexions: {e}", "error")
            return []
    
    def get_process_name(self, pid):
        """Obtenir le nom du processus à partir du PID"""
        try:
            if pid == 'N/A' or not pid.isdigit():
                return 'Unknown'
            
            process = psutil.Process(int(pid))
            return process.name()
        except Exception:
            return f"PID:{pid}"
    
    def analyze_connection(self, connection):
        """Analyse une connexion pour déterminer le type de trafic"""
        dst_port = connection.get('dst_port', 0)
        process_name = connection.get('process', '').lower()
        
        # Vérification liste blanche
        is_whitelisted = any(whitelist.lower() in process_name for whitelist in CONFIG['WHITELIST_PROCESSES'])
        connection['is_whitelisted'] = is_whitelisted
        
        if dst_port == 443:
            connection['service'] = 'HTTPS'
            connection['risk_level'] = 'LOW'
            connection['secure'] = True
        elif dst_port == 80:
            connection['service'] = 'HTTP'
            connection['risk_level'] = 'MEDIUM'
            connection['secure'] = False
        elif dst_port == 53:
            connection['service'] = 'DNS'
            connection['risk_level'] = 'LOW'
            connection['secure'] = True
        else:
            connection['service'] = f"Port_{dst_port}"
            connection['risk_level'] = 'HIGH' if dst_port in CONFIG['SUSPICIOUS_PORTS'] else 'MEDIUM'
            connection['secure'] = False
        
        connection['should_analyze'] = True
        
        return connection
    
    def start_capture(self):
        if self.is_capturing:
            return False
            
        self.is_capturing = True
        self.should_stop = False
        
        add_console_log("🎯 Capture du trafic RÉEL démarrée", "success")
        add_console_log("📊 Surveillance de TOUTES les connexions...", "info")
        
        def capture_loop():
            last_stats_time = time.time()
            packets_last_period = 0
            
            while self.is_capturing and not self.should_stop:
                try:
                    connections = self.get_active_connections_detailed()
                    new_connections = [conn for conn in connections if conn.get('connection_new', False)]
                    
                    for connection in new_connections:
                        analyzed_conn = self.analyze_connection(connection)
                        self.packets.append(analyzed_conn)
                        self.stats['total_packets'] += 1
                        packets_last_period += 1
                        
                        # Log du trafic
                        traffic_display = {
                            'timestamp': datetime.now().strftime('%H:%M:%S'),
                            'process': analyzed_conn['process'],
                            'destination': f"{analyzed_conn['dst_ip']}:{analyzed_conn['dst_port']}",
                            'service': analyzed_conn['service'],
                            'secure': analyzed_conn.get('secure', True),
                            'risk_level': analyzed_conn['risk_level'],
                            'is_whitelisted': analyzed_conn.get('is_whitelisted', False)
                        }
                        add_traffic_log(traffic_display)
                        
                        # Ajouter aux sites non sécurisés si HTTP
                        if not analyzed_conn.get('secure', True):
                            insecure_site = {
                                'timestamp': datetime.now().strftime('%H:%M:%S'),
                                'service': analyzed_conn['service'],
                                'process': analyzed_conn['process'],
                                'destination': f"{analyzed_conn['dst_ip']}:{analyzed_conn['dst_port']}",
                                'risk_level': analyzed_conn['risk_level']
                            }
                            add_insecure_site(insecure_site)
                        
                        # Log console
                        emoji = "🔒" if analyzed_conn['secure'] else "🔓"
                        whitelist_emoji = "✅" if analyzed_conn.get('is_whitelisted', False) else ""
                        risk_emoji = "⚠️" if analyzed_conn['risk_level'] == 'HIGH' else "✅" if analyzed_conn['risk_level'] == 'LOW' else "🔸"
                        log_message = f"{emoji} {risk_emoji} {whitelist_emoji} {analyzed_conn['process']} -> {analyzed_conn['dst_ip']}:{analyzed_conn['dst_port']} ({analyzed_conn['service']})"
                        add_console_log(log_message, "traffic")
                    
                    current_time = time.time()
                    if current_time - last_stats_time > 10:
                        if packets_last_period > 0:
                            stats_msg = f"📈 {packets_last_period} nouvelles connexions/10s"
                            add_console_log(stats_msg, "info")
                        packets_last_period = 0
                        last_stats_time = current_time
                    
                    time.sleep(2)
                    
                except Exception as e:
                    add_console_log(f"❌ Erreur capture: {e}", "error")
                    time.sleep(5)
            
            self.is_capturing = False
            add_console_log("🛑 Capture réseau arrêtée", "info")
        
        self.capture_thread = threading.Thread(target=capture_loop)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        return True
    
    def stop_capture(self):
        if self.is_capturing:
            self.should_stop = True
            add_console_log("✅ Capture réseau arrêtée", "success")
            return True
        return False
    
    def get_recent_packets(self, count=50):
        return self.packets[-count:] if self.packets else []
    
    def get_stats(self):
        return self.stats
class MLTrafficDetector:
    def __init__(self, traffic_collector, ml_classifier):
        self.traffic_collector = traffic_collector
        self.ml_classifier = ml_classifier
        self.alerts = deque(maxlen=200)
        self.is_monitoring = False
        self.monitor_thread = None
        self.should_stop_monitoring = False
        self.stats = {
            'attacks_detected': 0, 
            'total_processed': 0, 
            'ml_predictions': 0
        }
        self.recent_alerts = {}
        self.alert_count_minute = 0
        self.last_alert_reset = time.time()
        add_console_log("✅ Détecteur ML initialisé")
    
    def should_generate_alert(self, packet, ml_result):
        """Détermine si une alerte doit être générée"""
        try:
            current_time = time.time()
            if current_time - self.last_alert_reset > 60:
                self.alert_count_minute = 0
                self.last_alert_reset = current_time
            
            if self.alert_count_minute >= CONFIG['MAX_ALERTS_PER_MINUTE']:
                return False
            
            if packet.get('is_whitelisted', False):
                return False
            
            alert_id = f"{packet['src_ip']}-{packet['dst_ip']}-{packet['dst_port']}-{ml_result.get('attack_type', 'UNKNOWN')}"
            
            if alert_id in self.recent_alerts:
                if current_time - self.recent_alerts[alert_id] < CONFIG['ALERT_DEDUPLICATION_WINDOW']:
                    return False
            
            self.recent_alerts[alert_id] = current_time
            self.alert_count_minute += 1
            
            # Nettoyer le cache
            old_alerts = [aid for aid, timestamp in self.recent_alerts.items() 
                         if current_time - timestamp > CONFIG['ALERT_DEDUPLICATION_WINDOW']]
            for old_alert in old_alerts:
                del self.recent_alerts[old_alert]
            
            return True
        except Exception as e:
            add_console_log(f"❌ Erreur should_generate_alert: {e}", "error")
            return False
    
    def analyze_traffic(self):
        """Analyse le trafic avec le modèle ML"""
        while self.is_monitoring and not self.should_stop_monitoring:
            try:
                packets = self.traffic_collector.get_recent_packets(30)
                
                for packet in packets:
                    if self.should_stop_monitoring:
                        break
                    
                    self.stats['total_processed'] += 1
                    
                    # CORRECTION : Vérifier si c'est du HTTP et le traiter
                    dst_port = packet.get('dst_port', 0)
                    process_name = packet.get('process', '').lower()
                    
                    # Détection HTTP non sécurisé
                    if dst_port == 80 and not packet.get('is_whitelisted', False):
                        try:
                            alert_id = len(self.alerts) + 1
                            alert_data = {
                                'id': alert_id,
                                'timestamp': datetime.now().strftime('%H:%M:%S'),
                                'src_ip': packet.get('src_ip', 'Unknown'),
                                'dst_ip': packet.get('dst_ip', 'Unknown'),
                                'src_port': packet.get('src_port', 0),
                                'dst_port': packet.get('dst_port', 0),
                                'protocol': packet.get('protocol', 'TCP'),
                                'process': packet.get('process', 'Unknown'),
                                'attack_type': 'HTTP_NON_SECURE',
                                'confidence': 0.95,
                                'probability_attack': 0.95,
                                'severity': 'HIGH',
                                'service': 'HTTP',
                                'secure': False,
                                'ml_model': False,
                                'reason': 'Trafic HTTP non chiffré détecté',
                                'features_used': 0
                            }
                            
                            # CORRECTION : Ajouter directement sans vérification de déduplication pour HTTP
                            self.alerts.append(alert_data)
                            self.stats['attacks_detected'] += 1
                            add_alert_log(alert_data)
                            
                            # Log détaillé
                            add_console_log(f"🔍 DÉTECTION HTTP: {process_name} -> {packet.get('dst_ip')}:{dst_port}", "info")
                            add_console_log(f"🚨 ALERTE HTTP #{alert_id}: Site non sécurisé détecté!", "alert")
                            
                            continue  # Passer au paquet suivant
                            
                        except Exception as e:
                            add_console_log(f"❌ Erreur création alerte HTTP: {e}", "error")
                            continue
                    
                    # Log d'analyse pour debugging
                    add_console_log(f"🔍 ANALYSE: {process_name} -> {packet.get('dst_ip')}:{dst_port} (Port: {dst_port})", "info")
                    
                    # Pour les autres connexions, utiliser le ML
                    try:
                        ml_result = self.ml_classifier.predict(packet)
                        self.stats['ml_predictions'] += 1
                        
                        debug_msg = f"🤖 PRÉDICTION: {ml_result['prediction']} | Confiance: {ml_result['confidence']:.1%} | Raison: {ml_result['reason']}"
                        add_console_log(debug_msg, "info")
                        
                        # Générer alerte si détection ML
                        if (ml_result['prediction'] == 'ATTACK' and 
                            ml_result['confidence'] > CONFIG['ML_CONFIDENCE_THRESHOLD'] and
                            not packet.get('is_whitelisted', False)):
                            
                            attack_type = self.classify_attack(packet, ml_result)
                            alert_id = len(self.alerts) + 1
                            
                            alert_data = {
                                'id': alert_id,
                                'timestamp': datetime.now().strftime('%H:%M:%S'),
                                'src_ip': packet.get('src_ip', 'Unknown'),
                                'dst_ip': packet.get('dst_ip', 'Unknown'),
                                'src_port': packet.get('src_port', 0),
                                'dst_port': packet.get('dst_port', 0),
                                'protocol': packet.get('protocol', 'TCP'),
                                'process': packet.get('process', 'Unknown'),
                                'attack_type': attack_type,
                                'confidence': float(round(ml_result.get('confidence', 0), 3)),
                                'probability_attack': float(round(ml_result.get('probability_attack', 0), 3)),
                                'severity': self.calculate_severity(ml_result, packet),
                                'service': packet.get('service', 'Unknown'),
                                'secure': packet.get('secure', True),
                                'ml_model': True,
                                'reason': ml_result.get('reason', 'Raison inconnue'),
                                'features_used': ml_result.get('features_used', 0)
                            }
                            
                            if self.should_generate_alert(packet, alert_data):
                                self.alerts.append(alert_data)
                                self.stats['attacks_detected'] += 1
                                add_alert_log(alert_data)
                                add_console_log(f"🚨 ALERTE ML #{alert_id}: {attack_type} (Conf: {ml_result['confidence']:.1%})", "alert")
                    except Exception as e:
                        add_console_log(f"❌ Erreur analyse ML: {e}", "error")
                
                time.sleep(2)
                
            except Exception as e:
                add_console_log(f"❌ Erreur analyse trafic: {e}", "error")
                time.sleep(3)
    
    def classify_attack(self, packet, ml_result):
        """Classifie le type d'attaque"""
        try:
            dst_port = packet.get('dst_port', 0)
            probability_attack = ml_result.get('probability_attack', 0)
            
            if probability_attack > 0.9:
                return "ATTACK_HIGH_CONFIDENCE"
            elif probability_attack > 0.8:
                if dst_port in CONFIG['SUSPICIOUS_PORTS']:
                    return "SUSPICIOUS_PORT_ACCESS"
                else:
                    return "ANOMALY_DETECTED"
            else:
                return "SUSPICIOUS_ACTIVITY"
        except:
            return "UNKNOWN_ATTACK"
    
    def calculate_severity(self, ml_result, packet):
        """Calcule la sévérité de l'alerte"""
        try:
            confidence = ml_result.get('confidence', 0.0)
            
            if confidence > 0.9:
                return "CRITICAL"
            elif confidence > 0.8:
                return "HIGH"
            elif confidence > 0.7:
                return "MEDIUM"
            else:
                return "LOW"
        except:
            return "LOW"
    
    def start_monitoring(self):
        if self.is_monitoring:
            return False
            
        self.is_monitoring = True
        self.should_stop_monitoring = False
        
        if not self.ml_classifier.is_trained:
            add_console_log("⚠️  Entraînement du modèle ML en cours...", "warning")
            self.ml_classifier.train_model()
        
        add_console_log("🔍 Détection ML activée", "success")
        add_console_log(f"🤖 Seuil de confiance: {CONFIG['ML_CONFIDENCE_THRESHOLD']}", "info")
        
        self.monitor_thread = threading.Thread(target=self.analyze_traffic)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        return True
    
    def stop_monitoring(self):
        if self.is_monitoring:
            self.should_stop_monitoring = True
            self.is_monitoring = False
            add_console_log("✅ Détection ML arrêtée", "success")
            return True
        return False
    
    def get_recent_alerts(self, count=20):
        """Récupère les alertes récentes avec gestion d'erreurs"""
        try:
            alerts = list(self.alerts)[-count:]
            # Nettoyer les données pour JSON
            cleaned_alerts = []
            for alert in alerts:
                cleaned_alert = {}
                for key, value in alert.items():
                    # Convertir les types non sérialisables
                    if isinstance(value, (np.integer, np.floating)):
                        cleaned_alert[key] = float(value)
                    elif isinstance(value, (np.bool_)):
                        cleaned_alert[key] = bool(value)
                    elif isinstance(value, (np.ndarray)):
                        cleaned_alert[key] = value.tolist()
                    else:
                        cleaned_alert[key] = value
                cleaned_alerts.append(cleaned_alert)
            return cleaned_alerts
        except Exception as e:
            add_console_log(f"❌ Erreur get_recent_alerts: {e}", "error")
            return []
    
    def get_stats(self):
        """Récupère les statistiques avec gestion d'erreurs - CORRECTION APPLIQUÉE"""
        try:
            detection_rate = 0.0  # CORRECTION : Initialiser à 0.0
            if self.stats['total_processed'] > 0:
                detection_rate = (self.stats['attacks_detected'] / self.stats['total_processed']) * 100
            
            return {
                'total_processed': int(self.stats['total_processed']),
                'attacks_detected': int(self.stats['attacks_detected']),
                'ml_predictions': int(self.stats.get('ml_predictions', 0)),
                'detection_rate': float(round(detection_rate, 2)),
                'is_monitoring': bool(self.is_monitoring),
                'alerts_this_minute': int(self.alert_count_minute)
            }
        except Exception as e:
            add_console_log(f"❌ Erreur get_stats: {e}", "error")
            return {
                'total_processed': 0,
                'attacks_detected': 0,
                'ml_predictions': 0,
                'detection_rate': 0.0,
                'is_monitoring': False,
                'alerts_this_minute': 0
            }
    
    def debug_alerts(self):
        """Affiche des informations de debug sur les alertes"""
        print(f"🔍 DEBUG ALERTES:")
        print(f"   Nombre total d'alertes: {len(self.alerts)}")
        print(f"   Alertes détectées: {self.stats['attacks_detected']}")
        print(f"   Dernières alertes:")
        for i, alert in enumerate(list(self.alerts)[-5:]):
            print(f"     {i+1}. {alert.get('attack_type', 'Unknown')} - {alert.get('process', 'Unknown')}")
        
        # Vérifier la capture HTTP
        print(f"   Capture active: {self.traffic_collector.is_capturing}")
        print(f"   Détection active: {self.is_monitoring}")
    
    
    
    
def analyze_traffic(self):
    """Analyse le trafic avec le modèle ML"""
    while self.is_monitoring and not self.should_stop_monitoring:
        try:
            packets = self.traffic_collector.get_recent_packets(30)
            
            for packet in packets:
                if self.should_stop_monitoring:
                    break
                
                self.stats['total_processed'] += 1
                
                # CORRECTION : Vérifier si c'est du HTTP et le traiter
                dst_port = packet.get('dst_port', 0)
                process_name = packet.get('process', '').lower()
                
                # Détection HTTP non sécurisé - CORRECTION COMPLÈTE
                if dst_port == 80 and not packet.get('is_whitelisted', False):
                    try:
                        alert_id = len(self.alerts) + 1
                        alert_data = {
                            'id': alert_id,
                            'timestamp': datetime.now().strftime('%H:%M:%S'),
                            'src_ip': packet.get('src_ip', 'Unknown'),
                            'dst_ip': packet.get('dst_ip', 'Unknown'),
                            'src_port': packet.get('src_port', 0),
                            'dst_port': packet.get('dst_port', 0),
                            'protocol': packet.get('protocol', 'TCP'),
                            'process': packet.get('process', 'Unknown'),
                            'attack_type': 'HTTP_NON_SECURE',
                            'confidence': 0.95,
                            'probability_attack': 0.95,
                            'severity': 'HIGH',
                            'service': 'HTTP',
                            'secure': False,
                            'ml_model': False,
                            'reason': 'Trafic HTTP non chiffré détecté',
                            'features_used': 0
                        }
                        
                        # CORRECTION : Ajouter directement sans vérification de déduplication pour HTTP
                        self.alerts.append(alert_data)
                        self.stats['attacks_detected'] += 1
                        add_alert_log(alert_data)
                        
                        # Log détaillé
                        add_console_log(f"🔍 DÉTECTION HTTP: {process_name} -> {packet.get('dst_ip')}:{dst_port}", "info")
                        add_console_log(f"🚨 ALERTE HTTP #{alert_id}: Site non sécurisé détecté!", "alert")
                        
                        continue  # Passer au paquet suivant
                        
                    except Exception as e:
                        add_console_log(f"❌ Erreur création alerte HTTP: {e}", "error")
                        continue
                
                # Log d'analyse pour debugging
                add_console_log(f"🔍 ANALYSE: {process_name} -> {packet.get('dst_ip')}:{dst_port} (Port: {dst_port})", "info")
                
                # Pour les autres connexions, utiliser le ML
                try:
                    ml_result = self.ml_classifier.predict(packet)
                    self.stats['ml_predictions'] += 1
                    
                    debug_msg = f"🤖 PRÉDICTION: {ml_result['prediction']} | Confiance: {ml_result['confidence']:.1%} | Raison: {ml_result['reason']}"
                    add_console_log(debug_msg, "info")
                    
                    # Générer alerte si détection ML
                    if (ml_result['prediction'] == 'ATTACK' and 
                        ml_result['confidence'] > CONFIG['ML_CONFIDENCE_THRESHOLD'] and
                        not packet.get('is_whitelisted', False)):
                        
                        attack_type = self.classify_attack(packet, ml_result)
                        alert_id = len(self.alerts) + 1
                        
                        alert_data = {
                            'id': alert_id,
                            'timestamp': datetime.now().strftime('%H:%M:%S'),
                            'src_ip': packet.get('src_ip', 'Unknown'),
                            'dst_ip': packet.get('dst_ip', 'Unknown'),
                            'src_port': packet.get('src_port', 0),
                            'dst_port': packet.get('dst_port', 0),
                            'protocol': packet.get('protocol', 'TCP'),
                            'process': packet.get('process', 'Unknown'),
                            'attack_type': attack_type,
                            'confidence': float(round(ml_result.get('confidence', 0), 3)),
                            'probability_attack': float(round(ml_result.get('probability_attack', 0), 3)),
                            'severity': self.calculate_severity(ml_result, packet),
                            'service': packet.get('service', 'Unknown'),
                            'secure': packet.get('secure', True),
                            'ml_model': True,
                            'reason': ml_result.get('reason', 'Raison inconnue'),
                            'features_used': ml_result.get('features_used', 0)
                        }
                        
                        if self.should_generate_alert(packet, alert_data):
                            self.alerts.append(alert_data)
                            self.stats['attacks_detected'] += 1
                            add_alert_log(alert_data)
                            add_console_log(f"🚨 ALERTE ML #{alert_id}: {attack_type} (Conf: {ml_result['confidence']:.1%})", "alert")
                except Exception as e:
                    add_console_log(f"❌ Erreur analyse ML: {e}", "error")
            
            time.sleep(2)
            
        except Exception as e:
            add_console_log(f"❌ Erreur analyse trafic: {e}", "error")
            time.sleep(3)
    
    def classify_attack(self, packet, ml_result):
        """Classifie le type d'attaque"""
        try:
            dst_port = packet.get('dst_port', 0)
            probability_attack = ml_result.get('probability_attack', 0)
            
            if probability_attack > 0.9:
                return "ATTACK_HIGH_CONFIDENCE"
            elif probability_attack > 0.8:
                if dst_port in CONFIG['SUSPICIOUS_PORTS']:
                    return "SUSPICIOUS_PORT_ACCESS"
                else:
                    return "ANOMALY_DETECTED"
            else:
                return "SUSPICIOUS_ACTIVITY"
        except:
            return "UNKNOWN_ATTACK"
    
    def calculate_severity(self, ml_result, packet):
        """Calcule la sévérité de l'alerte"""
        try:
            confidence = ml_result.get('confidence', 0.0)
            
            if confidence > 0.9:
                return "CRITICAL"
            elif confidence > 0.8:
                return "HIGH"
            elif confidence > 0.7:
                return "MEDIUM"
            else:
                return "LOW"
        except:
            return "LOW"
    
    def start_monitoring(self):
        if self.is_monitoring:
            return False
            
        self.is_monitoring = True
        self.should_stop_monitoring = False
        
        if not self.ml_classifier.is_trained:
            add_console_log("⚠️  Entraînement du modèle ML en cours...", "warning")
            self.ml_classifier.train_model()
        
        add_console_log("🔍 Détection ML activée", "success")
        add_console_log(f"🤖 Seuil de confiance: {CONFIG['ML_CONFIDENCE_THRESHOLD']}", "info")
        
        self.monitor_thread = threading.Thread(target=self.analyze_traffic)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        return True
    
    def stop_monitoring(self):
        if self.is_monitoring:
            self.should_stop_monitoring = True
            self.is_monitoring = False
            add_console_log("✅ Détection ML arrêtée", "success")
            return True
        return False
    
    def get_recent_alerts(self, count=20):
        """Récupère les alertes récentes avec gestion d'erreurs"""
        try:
            alerts = list(self.alerts)[-count:]
            # Nettoyer les données pour JSON
            cleaned_alerts = []
            for alert in alerts:
                cleaned_alert = {}
                for key, value in alert.items():
                    # Convertir les types non sérialisables
                    if isinstance(value, (np.integer, np.floating)):
                        cleaned_alert[key] = float(value)
                    elif isinstance(value, (np.bool_)):
                        cleaned_alert[key] = bool(value)
                    elif isinstance(value, (np.ndarray)):
                        cleaned_alert[key] = value.tolist()
                    else:
                        cleaned_alert[key] = value
                cleaned_alerts.append(cleaned_alert)
            return cleaned_alerts
        except Exception as e:
            add_console_log(f"❌ Erreur get_recent_alerts: {e}", "error")
            return []
    
    def get_stats(self):
        """Récupère les statistiques avec gestion d'erreurs"""
        try:
            detection_rate = 0
            if self.stats['total_processed'] > 0:
                detection_rate = (self.stats['attacks_detected'] / self.stats['total_processed']) * 100
            
            return {
                'total_processed': int(self.stats['total_processed']),
                'attacks_detected': int(self.stats['attacks_detected']),
                'ml_predictions': int(self.stats.get('ml_predictions', 0)),
                'detection_rate': float(round(detection_rate, 2)),
                'is_monitoring': bool(self.is_monitoring),
                'alerts_this_minute': int(self.alert_count_minute)
            }
        except Exception as e:
            add_console_log(f"❌ Erreur get_stats: {e}", "error")
            return {
                'total_processed': 0,
                'attacks_detected': 0,
                'ml_predictions': 0,
                'detection_rate': 0.0,
                'is_monitoring': False,
                'alerts_this_minute': 0
            }

# Initialisation - MAINTENANT TOUTES LES CLASSES SONT DÉFINIES
ml_classifier = MLTrafficClassifier()
traffic_collector = RealNetworkCapture()
detector = MLTrafficDetector(traffic_collector, ml_classifier)

# Routes Flask
# Routes Flask - VERSION CORRIGÉE SANS DOUBLONS

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/stats')
def api_stats():
    try:
        traffic_stats = traffic_collector.get_stats()
        detection_stats = detector.get_stats()
        model_info = ml_classifier.get_model_info()
        
        return jsonify({
            'traffic': traffic_stats,
            'detection': detection_stats,
            'model_info': model_info,
            'system_status': {
                'capture_active': traffic_collector.is_capturing,
                'detection_active': detector.is_monitoring,
                'model_trained': ml_classifier.is_trained
            }
        })
    except Exception as e:
        print("❌ ERREUR DÉTAILLÉE /api/stats:")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/console_logs')
def api_console_logs():
    try:
        return jsonify({'logs': list(console_logs)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/traffic_logs')
def api_traffic_logs():
    try:
        return jsonify({'traffic': list(traffic_logs)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alert_logs')
def api_alert_logs():
    try:
        alerts = detector.get_recent_alerts(50)
        return jsonify({'alerts': alerts})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/alerts')
def api_alerts():
    try:
        count = request.args.get('count', 10, type=int)
        alerts = detector.get_recent_alerts(count)
        return jsonify({'alerts': alerts})
    except Exception as e:
        print("❌ ERREUR DÉTAILLÉE /api/alerts:")
        print(traceback.format_exc())
        return jsonify({'error': str(e)}), 500

@app.route('/api/insecure_sites')
def api_insecure_sites():
    try:
        return jsonify({'insecure_sites': list(insecure_sites_logs)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/control/start_capture', methods=['POST'])
def api_start_capture():
    try:
        success = traffic_collector.start_capture()
        if success:
            add_console_log("🎯 Capture réseau démarrée par l'utilisateur", "success")
            return jsonify({'status': 'success', 'message': 'Capture démarrée'})
        else:
            return jsonify({'status': 'error', 'message': 'La capture était déjà active'})
    except Exception as e:
        add_console_log(f"❌ Erreur démarrage capture: {e}", "error")
        return jsonify({'error': str(e)}), 500

@app.route('/api/control/stop_capture', methods=['POST'])
def api_stop_capture():
    try:
        success = traffic_collector.stop_capture()
        if success:
            add_console_log("🛑 Capture réseau arrêtée par l'utilisateur", "success")
            return jsonify({'status': 'success', 'message': 'Capture arrêtée'})
        else:
            return jsonify({'status': 'error', 'message': 'La capture n\'était pas active'})
    except Exception as e:
        add_console_log(f"❌ Erreur arrêt capture: {e}", "error")
        return jsonify({'error': str(e)}), 500

@app.route('/api/control/start_detection', methods=['POST'])
def api_start_detection():
    try:
        success = detector.start_monitoring()
        if success:
            add_console_log("🔍 Détection ML activée par l'utilisateur", "success")
            return jsonify({'status': 'success', 'message': 'Détection ML activée'})
        else:
            return jsonify({'status': 'error', 'message': 'La détection ML était déjà active'})
    except Exception as e:
        add_console_log(f"❌ Erreur activation détection ML: {e}", "error")
        return jsonify({'error': str(e)}), 500

@app.route('/api/control/stop_detection', methods=['POST'])
def api_stop_detection():
    try:
        success = detector.stop_monitoring()
        if success:
            add_console_log("⏸️ Détection ML arrêtée par l'utilisateur", "success")
            return jsonify({'status': 'success', 'message': 'Détection ML arrêtée'})
        else:
            return jsonify({'status': 'error', 'message': 'La détection ML n\'était pas active'})
    except Exception as e:
        add_console_log(f"❌ Erreur arrêt détection ML: {e}", "error")
        return jsonify({'error': str(e)}), 500

@app.route('/api/control/train_model', methods=['POST'])
def api_train_model():
    try:
        accuracy = ml_classifier.train_model()
        if accuracy > 0:
            add_console_log(f"🤖 Modèle ML entraîné avec succès (Accuracy: {accuracy:.2%})", "success")
            return jsonify({
                'status': 'success', 
                'message': f'Modèle ML entraîné (Accuracy: {accuracy:.2%})',
                'accuracy': accuracy,
                'model_info': ml_classifier.get_model_info()
            })
        else:
            return jsonify({'status': 'error', 'message': 'Erreur lors de l\'entraînement du modèle'})
    except Exception as e:
        add_console_log(f"❌ Erreur entraînement modèle: {e}", "error")
        return jsonify({'error': str(e)}), 500

@app.route('/api/control/load_model', methods=['POST'])
def api_load_model():
    try:
        success = ml_classifier.load_model()
        if success:
            add_console_log("📂 Modèle ML chargé avec succès", "success")
            return jsonify({'status': 'success', 'message': 'Modèle ML chargé','model_info': ml_classifier.get_model_info()})
        else:
            return jsonify({'status': 'error', 'message': 'Aucun modèle sauvegardé trouvé'})
    except Exception as e:
        add_console_log(f"❌ Erreur chargement modèle: {e}", "error")
        return jsonify({'error': str(e)}), 500

@app.route('/api/control/clear_logs', methods=['POST'])
def api_clear_logs():
    try:
        # Effacer tous les logs
        console_logs.clear()
        traffic_logs.clear()
        alert_logs.clear()
        insecure_sites_logs.clear()
        
        # Effacer aussi les alertes du détecteur
        detector.alerts.clear()
        detector.stats['attacks_detected'] = 0
        detector.stats['total_processed'] = 0
        detector.stats['ml_predictions'] = 0
        detector.alert_count_minute = 0
        detector.recent_alerts.clear()
        
        add_console_log("🗑️ Tous les logs et alertes effacés par l'utilisateur", "success")
        return jsonify({'status': 'success', 'message': 'Logs et alertes effacés'})
    except Exception as e:
        add_console_log(f"❌ Erreur effacement logs: {e}", "error")
        return jsonify({'error': str(e)}), 500

@app.route('/api/test/alert', methods=['POST', 'GET'])
def api_test_alert():
    """Génère une alerte de test manuellement"""
    try:
        alert_id = len(detector.alerts) + 1
        
        test_alert = {
            'id': alert_id,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'src_ip': '192.168.1.100',
            'dst_ip': '93.184.216.34',
            'src_port': 54321,
            'dst_port': 80,
            'protocol': 'TCP',
            'process': 'chrome.exe',
            'attack_type': 'HTTP_NON_SECURE',
            'confidence': 0.85,
            'probability_attack': 0.85,
            'severity': 'MEDIUM',
            'service': 'HTTP',
            'secure': False,
            'ml_model': False,
            'reason': 'ALERTE TEST: Navigation HTTP détectée',
            'features_used': 0
        }
        
        detector.alerts.append(test_alert)
        detector.stats['attacks_detected'] += 1
        add_alert_log(test_alert)
        
        add_console_log(f"🧪 ALERTE TEST #{alert_id} générée avec succès!", "success")
        
        return jsonify({
            'status': 'success', 
            'message': f'Alerte de test #{alert_id} créée',
            'alert': test_alert
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Vider les alertes existantes au démarrage
    detector.alerts.clear()
    alert_logs.clear()
    
    add_console_log("🎯 SYSTÈME IDS COMPLET AVEC MACHINE LEARNING", "success")
    add_console_log("🤖 Random Forest avec réduction des faux positifs", "info")
    add_console_log("🔍 Trafic browser légitime ignoré", "info")
    add_console_log("🌐 Détection HTTP activée - Les connexions non sécurisées apparaîtront dans les alertes", "info")
    add_console_log("🌐 Accédez à: http://localhost:5000", "info")
    
    # Essayer de charger un modèle pré-existant
    ml_classifier.load_model()
    
    app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)
    
    