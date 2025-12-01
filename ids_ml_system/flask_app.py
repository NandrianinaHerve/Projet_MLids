# ids_ml_system/flask_app.py
"""Application Flask principale"""
import os
import traceback
from flask import Flask, render_template, jsonify, request
from datetime import datetime

# Import des modules
from .config import console_logs, traffic_logs, alert_logs, insecure_sites_logs, CONFIG
from .logger import Logger
from .ml_model import MLTrafficClassifier
from .network_capture import RealNetworkCapture
from .traffic_detector import MLTrafficDetector

class IDSFlaskApp:
    def __init__(self, template_folder=None):
        # Déterminer le dossier des templates
        if template_folder is None:
            # Chercher le dossier templates dans le répertoire parent
            current_dir = os.path.dirname(os.path.abspath(__file__))
            parent_dir = os.path.dirname(current_dir)
            template_folder = os.path.join(parent_dir, 'templates')
        
        # Vérifier si le dossier templates existe
        if not os.path.exists(template_folder):
            print(f"⚠️  Dossier templates non trouvé à: {template_folder}")
            # Créer le dossier templates si nécessaire
            os.makedirs(template_folder, exist_ok=True)
            print(f"✅ Dossier templates créé: {template_folder}")
        
        print(f"📁 Dossier templates utilisé: {template_folder}")
        
        # Initialiser Flask avec le bon dossier de templates
        self.app = Flask(__name__, template_folder=template_folder)
        self.setup_components()
        self.setup_routes()
    
    def setup_components(self):
        """Initialise tous les composants"""
        # Initialiser les composants
        self.ml_classifier = MLTrafficClassifier()
        self.traffic_collector = RealNetworkCapture()
        self.detector = MLTrafficDetector(self.traffic_collector, self.ml_classifier)
        
        # Vider les alertes existantes au démarrage
        self.detector.alerts.clear()
        alert_logs.clear()
        
        Logger.add_console_log("🎯 SYSTÈME IDS COMPLET AVEC MACHINE LEARNING", "success")
        Logger.add_console_log("🤖 Random Forest avec réduction des faux positifs", "info")
        Logger.add_console_log("🔍 Trafic browser légitime ignoré", "info")
        Logger.add_console_log("🌐 Détection HTTP activée - Les connexions non sécurisées apparaîtront dans les alertes", "info")
        Logger.add_console_log("🌐 Accédez à: http://localhost:5000", "info")
        
        # Essayer de charger un modèle pré-existant
        self.ml_classifier.load_model()
    
    def setup_routes(self):
        """Configure toutes les routes Flask"""
        
        @self.app.route('/')
        def index():
            try:
                # Debug: Vérifier le chemin des templates
                print(f"🔍 Tentative de chargement de index.html depuis: {self.app.template_folder}")
                
                # Lister les fichiers dans le dossier templates
                if os.path.exists(self.app.template_folder):
                    template_files = os.listdir(self.app.template_folder)
                    print(f"📄 Fichiers dans templates: {template_files}")
                
                return render_template('index.html')
            except Exception as e:
                print(f"❌ Erreur lors du chargement du template: {e}")
                traceback.print_exc()
                return f"""
                <html>
                <head><title>Erreur Template</title></head>
                <body>
                    <h1>Erreur de chargement du template</h1>
                    <p>Message: {str(e)}</p>
                    <p>Dossier templates: {self.app.template_folder}</p>
                    <p>Vérifiez que index.html se trouve dans le dossier templates.</p>
                </body>
                </html>
                """, 500
        
        @self.app.route('/api/stats')
        def api_stats():
            try:
                traffic_stats = self.traffic_collector.get_stats()
                detection_stats = self.detector.get_stats()
                model_info = self.ml_classifier.get_model_info()
                
                return jsonify({
                    'traffic': traffic_stats,
                    'detection': detection_stats,
                    'model_info': model_info,
                    'system_status': {
                        'capture_active': self.traffic_collector.is_capturing,
                        'detection_active': self.detector.is_monitoring,
                        'model_trained': self.ml_classifier.is_trained
                    }
                })
            except Exception as e:
                print("❌ ERREUR DÉTAILLÉE /api/stats:")
                print(traceback.format_exc())
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/console_logs')
        def api_console_logs():
            try:
                return jsonify({'logs': list(console_logs)})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/traffic_logs')
        def api_traffic_logs():
            try:
                return jsonify({'traffic': list(traffic_logs)})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/alert_logs')
        def api_alert_logs():
            try:
                alerts = self.detector.get_recent_alerts(50)
                return jsonify({'alerts': alerts})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/alerts')
        def api_alerts():
            try:
                count = request.args.get('count', 10, type=int)
                alerts = self.detector.get_recent_alerts(count)
                return jsonify({'alerts': alerts})
            except Exception as e:
                print("❌ ERREUR DÉTAILLÉE /api/alerts:")
                print(traceback.format_exc())
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/insecure_sites')
        def api_insecure_sites():
            try:
                return jsonify({'insecure_sites': list(insecure_sites_logs)})
            except Exception as e:
                return jsonify({'error': str(e)}), 500
        
        # Routes de contrôle
        @self.app.route('/api/control/start_capture', methods=['POST'])
        def api_start_capture():
            try:
                success = self.traffic_collector.start_capture()
                if success:
                    Logger.add_console_log("🎯 Capture réseau démarrée par l'utilisateur", "success")
                    return jsonify({'status': 'success', 'message': 'Capture démarrée'})
                else:
                    return jsonify({'status': 'error', 'message': 'La capture était déjà active'})
            except Exception as e:
                Logger.add_console_log(f"❌ Erreur démarrage capture: {e}", "error")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/control/stop_capture', methods=['POST'])
        def api_stop_capture():
            try:
                success = self.traffic_collector.stop_capture()
                if success:
                    Logger.add_console_log("🛑 Capture réseau arrêtée par l'utilisateur", "success")
                    return jsonify({'status': 'success', 'message': 'Capture arrêtée'})
                else:
                    return jsonify({'status': 'error', 'message': 'La capture n\'était pas active'})
            except Exception as e:
                Logger.add_console_log(f"❌ Erreur arrêt capture: {e}", "error")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/control/start_detection', methods=['POST'])
        def api_start_detection():
            try:
                success = self.detector.start_monitoring()
                if success:
                    Logger.add_console_log("🔍 Détection ML activée par l'utilisateur", "success")
                    return jsonify({'status': 'success', 'message': 'Détection ML activée'})
                else:
                    return jsonify({'status': 'error', 'message': 'La détection ML était déjà active'})
            except Exception as e:
                Logger.add_console_log(f"❌ Erreur activation détection ML: {e}", "error")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/control/stop_detection', methods=['POST'])
        def api_stop_detection():
            try:
                success = self.detector.stop_monitoring()
                if success:
                    Logger.add_console_log("⏸️ Détection ML arrêtée par l'utilisateur", "success")
                    return jsonify({'status': 'success', 'message': 'Détection ML arrêtée'})
                else:
                    return jsonify({'status': 'error', 'message': 'La détection ML n\'était pas active'})
            except Exception as e:
                Logger.add_console_log(f"❌ Erreur arrêt détection ML: {e}", "error")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/control/train_model', methods=['POST'])
        def api_train_model():
            try:
                accuracy = self.ml_classifier.train_model()
                if accuracy > 0:
                    Logger.add_console_log(f"🤖 Modèle ML entraîné avec succès (Accuracy: {accuracy:.2%})", "success")
                    return jsonify({
                        'status': 'success', 
                        'message': f'Modèle ML entraîné (Accuracy: {accuracy:.2%})',
                        'accuracy': accuracy,
                        'model_info': self.ml_classifier.get_model_info()
                    })
                else:
                    return jsonify({'status': 'error', 'message': 'Erreur lors de l\'entraînement du modèle'})
            except Exception as e:
                Logger.add_console_log(f"❌ Erreur entraînement modèle: {e}", "error")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/control/load_model', methods=['POST'])
        def api_load_model():
            try:
                success = self.ml_classifier.load_model()
                if success:
                    Logger.add_console_log("📂 Modèle ML chargé avec succès", "success")
                    return jsonify({
                        'status': 'success', 
                        'message': 'Modèle ML chargé',
                        'model_info': self.ml_classifier.get_model_info()
                    })
                else:
                    return jsonify({'status': 'error', 'message': 'Aucun modèle sauvegardé trouvé'})
            except Exception as e:
                Logger.add_console_log(f"❌ Erreur chargement modèle: {e}", "error")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/control/clear_logs', methods=['POST'])
        def api_clear_logs():
            try:
                Logger.clear_all_logs()
                
                # Effacer aussi les alertes du détecteur
                self.detector.alerts.clear()
                self.detector.stats['attacks_detected'] = 0
                self.detector.stats['total_processed'] = 0
                self.detector.stats['ml_predictions'] = 0
                self.detector.alert_count_minute = 0
                self.detector.recent_alerts.clear()
                
                Logger.add_console_log("🗑️ Tous les logs et alertes effacés par l'utilisateur", "success")
                return jsonify({'status': 'success', 'message': 'Logs et alertes effacés'})
            except Exception as e:
                Logger.add_console_log(f"❌ Erreur effacement logs: {e}", "error")
                return jsonify({'error': str(e)}), 500
        
        @self.app.route('/api/test/alert', methods=['POST', 'GET'])
        def api_test_alert():
            """Génère une alerte de test manuellement"""
            try:
                alert_id = len(self.detector.alerts) + 1
                
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
                
                self.detector.alerts.append(test_alert)
                self.detector.stats['attacks_detected'] += 1
                Logger.add_alert_log(test_alert)
                
                Logger.add_console_log(f"🧪 ALERTE TEST #{alert_id} générée avec succès!", "success")
                
                return jsonify({
                    'status': 'success', 
                    'message': f'Alerte de test #{alert_id} créée',
                    'alert': test_alert
                })
                
            except Exception as e:
                return jsonify({'error': str(e)}), 500
    
    def run(self, host='0.0.0.0', port=5000, debug=True):
        """Lance l'application Flask"""
        print(f"🚀 Lancement de l'application IDS sur http://{host}:{port}")
        print(f"📁 Dossier templates: {self.app.template_folder}")
        self.app.run(host=host, port=port, debug=debug, use_reloader=False)