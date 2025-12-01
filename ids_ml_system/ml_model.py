# ids_ml_system/ml_model.py
"""Modèle de Machine Learning"""
import os
import random
import joblib
import numpy as np
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
from .preprocessor import MLDataPreprocessor
from .logger import Logger
from .config import CONFIG

class MLTrafficClassifier:
    def __init__(self):
        self.model = None
        self.is_trained = False
        self.accuracy = 0.0
        self.preprocessor = MLDataPreprocessor()
        Logger.add_console_log("✅ Classificateur ML initialisé")
    
    def load_model(self):
        """Charge un modèle pré-entraîné"""
        try:
            if os.path.exists('ids_ml_model.joblib'):
                model_data = joblib.load('ids_ml_model.joblib')
                self.model = model_data['model']
                self.preprocessor.scaler = model_data['scaler']
                self.accuracy = model_data['accuracy']
                self.is_trained = True
                Logger.add_console_log("📂 Modèle ML pré-entraîné chargé avec succès!", "success")
                Logger.add_console_log(f"📊 Accuracy du modèle chargé: {self.accuracy:.2%}", "success")
                return True
            else:
                Logger.add_console_log("ℹ️  Aucun modèle sauvegardé trouvé. Entraînement nécessaire.", "info")
                return False
        except Exception as e:
            Logger.add_console_log(f"❌ Erreur chargement modèle: {e}", "error")
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
        Logger.add_console_log("🤖 Génération des données d'entraînement...")
        
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
        
        Logger.add_console_log(f"✅ Données d'entraînement générées: {len(features_list)} échantillons")
        return np.array(features_list), np.array(labels_list)
    
    def train_model(self):
        """Entraîne le modèle Random Forest"""
        try:
            Logger.add_console_log("🎯 Début de l'entraînement du modèle ML...")
            
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
            
            Logger.add_console_log(f"✅ Modèle Random Forest entraîné avec succès!", "success")
            Logger.add_console_log(f"📊 Accuracy: {self.accuracy:.2%}", "success")
            
            self.save_model()
            return self.accuracy
            
        except Exception as e:
            Logger.add_console_log(f"❌ Erreur entraînement modèle: {e}", "error")
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
            Logger.add_console_log(f"❌ Erreur prédiction ML: {e}", "error")
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
            Logger.add_console_log("💾 Modèle ML sauvegardé: ids_ml_model.joblib", "success")
        except Exception as e:
            Logger.add_console_log(f"❌ Erreur sauvegarde modèle: {e}", "error")
    
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