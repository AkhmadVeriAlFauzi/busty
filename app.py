from flask import Flask
from flask_cors import CORS  # ✅ Import CORS
from routes import main, auth
from extensions import mongo, mail
from api.api import api
from dotenv import load_dotenv
import os
import redis
import uuid

# ⏬ Load isi .env
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY')

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

CORS(app) 

# Register Blueprints
app.register_blueprint(main)
app.register_blueprint(auth)
app.register_blueprint(api)

# Konfigurasi SMTP dari .env
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'True'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')



# Inisialisasi mail
mail.init_app(app)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

