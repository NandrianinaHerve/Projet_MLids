# main.py
"""Point d'entrée principal du système IDS"""
from ids_ml_system.flask_app import IDSFlaskApp

if __name__ == '__main__':
    # Créer et lancer l'application
    app = IDSFlaskApp()
    app.run()