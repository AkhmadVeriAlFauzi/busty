from flask import Flask
from flask_cors import CORS  # ✅ Import CORS
from routes import main, auth
from api.api import api

app = Flask(__name__)
app.secret_key = 'busty_secret_key'

CORS(app) 

# Register Blueprints
app.register_blueprint(main)
app.register_blueprint(auth)
app.register_blueprint(api)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

