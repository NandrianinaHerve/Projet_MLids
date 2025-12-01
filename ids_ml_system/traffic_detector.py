# ids_ml_system/traffic_detector.py
"""Détecteur de trafic avec ML"""
import time
from datetime import datetime
from collections import deque
import numpy as np
import threading
from .logger import Logger
from .config import CONFIG

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
        Logger.add_console_log("✅ Détecteur ML initialisé")
    
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
            old_alerts = [
                aid for aid, timestamp in self.recent_alerts.items() 
                if current_time - timestamp > CONFIG['ALERT_DEDUPLICATION_WINDOW']
            ]
            for old_alert in old_alerts:
                del self.recent_alerts[old_alert]
            
            return True
        except Exception as e:
            Logger.add_console_log(f"❌ Erreur should_generate_alert: {e}", "error")
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
                    
                    # Détection HTTP non sécurisé
                    dst_port = packet.get('dst_port', 0)
                    process_name = packet.get('process', '').lower()
                    
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
                            
                            self.alerts.append(alert_data)
                            self.stats['attacks_detected'] += 1
                            Logger.add_alert_log(alert_data)
                            
                            Logger.add_console_log(f"🔍 DÉTECTION HTTP: {process_name} -> {packet.get('dst_ip')}:{dst_port}", "info")
                            Logger.add_console_log(f"🚨 ALERTE HTTP #{alert_id}: Site non sécurisé détecté!", "alert")
                            
                            continue
                            
                        except Exception as e:
                            Logger.add_console_log(f"❌ Erreur création alerte HTTP: {e}", "error")
                            continue
                    
                    Logger.add_console_log(f"🔍 ANALYSE: {process_name} -> {packet.get('dst_ip')}:{dst_port} (Port: {dst_port})", "info")
                    
                    # Pour les autres connexions, utiliser le ML
                    try:
                        ml_result = self.ml_classifier.predict(packet)
                        self.stats['ml_predictions'] += 1
                        
                        debug_msg = f"🤖 PRÉDICTION: {ml_result['prediction']} | Confiance: {ml_result['confidence']:.1%} | Raison: {ml_result['reason']}"
                        Logger.add_console_log(debug_msg, "info")
                        
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
                                Logger.add_alert_log(alert_data)
                                Logger.add_console_log(f"🚨 ALERTE ML #{alert_id}: {attack_type} (Conf: {ml_result['confidence']:.1%})", "alert")
                    except Exception as e:
                        Logger.add_console_log(f"❌ Erreur analyse ML: {e}", "error")
                
                time.sleep(2)
                
            except Exception as e:
                Logger.add_console_log(f"❌ Erreur analyse trafic: {e}", "error")
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
            Logger.add_console_log("⚠️  Entraînement du modèle ML en cours...", "warning")
            self.ml_classifier.train_model()
        
        Logger.add_console_log("🔍 Détection ML activée", "success")
        Logger.add_console_log(f"🤖 Seuil de confiance: {CONFIG['ML_CONFIDENCE_THRESHOLD']}", "info")
        
        self.monitor_thread = threading.Thread(target=self.analyze_traffic)
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        return True
    
    def stop_monitoring(self):
        if self.is_monitoring:
            self.should_stop_monitoring = True
            self.is_monitoring = False
            Logger.add_console_log("✅ Détection ML arrêtée", "success")
            return True
        return False
    
    def get_recent_alerts(self, count=20):
        """Récupère les alertes récentes"""
        try:
            alerts = list(self.alerts)[-count:]
            cleaned_alerts = []
            for alert in alerts:
                cleaned_alert = {}
                for key, value in alert.items():
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
            Logger.add_console_log(f"❌ Erreur get_recent_alerts: {e}", "error")
            return []
    
    def get_stats(self):
        """Récupère les statistiques"""
        try:
            detection_rate = 0.0
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
            Logger.add_console_log(f"❌ Erreur get_stats: {e}", "error")
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
        
        print(f"   Capture active: {self.traffic_collector.is_capturing}")
        print(f"   Détection active: {self.is_monitoring}")