from flask import Flask
from flasgger import Swagger
from flask_cors import CORS  # ✅ Import CORS
from routes import main, auth
from extensions import mongo, mail, oauth
from api.api import api
from dotenv import load_dotenv
import os
import redis
import uuid
# import user_model


# ⏬ Load isi .env
load_dotenv()

app = Flask(__name__)
oauth.init_app(app)
google = oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    access_token_url='https://oauth2.googleapis.com/token',
    access_token_params=None,
    authorize_url='https://accounts.google.com/o/oauth2/auth',
    authorize_params=None,
    api_base_url='https://www.googleapis.com/oauth2/v1/',
    userinfo_endpoint='https://openidconnect.googleapis.com/v1/userinfo',
    client_kwargs={'scope': 'openid email profile'},
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
)
# user_model.google = google

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": 'apispec_1',
            "route": '/apispec_1.json',
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs",
    "securityDefinitions": {
        "ApiKeyAuth": {
            "type": "apiKey",
            "name": "x-api-key",
            "in": "header"
        },
        "Bearer": {
            "type": "apiKey",
            "name": "Authorization",
            "in": "header",
            "description": "Format: Bearer {token}"
        }
    },
}

swagger = Swagger(app, config=swagger_config)

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

