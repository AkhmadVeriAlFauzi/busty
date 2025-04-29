from flask import Blueprint, request, jsonify
from models.user import User
from pymongo import MongoClient

api = Blueprint('api', __name__, url_prefix='/api')

# Koneksi MongoDB
client = MongoClient('mongodb+srv://user:OG2QqFuCYwkoWBek@capstone.fqvkpyn.mongodb.net/?retryWrites=true&w=majority')
db = client['busty_db']
user_model = User(db)

@api.route('/register', methods=['POST'])
def api_register():
    data = request.get_json()

    username = data.get('username')
    email = data.get('email')
    no_hp = data.get('no_hp')
    password = data.get('password')

    if not all([username, email, no_hp, password]):
        return jsonify({'status': 'error', 'message': 'Semua field wajib diisi.'}), 400

    if user_model.find_by_email(email):
        return jsonify({'status': 'error', 'message': 'Email sudah terdaftar.'}), 409

    if user_model.find_by_username(username):
        return jsonify({'status': 'error', 'message': 'Username sudah terdaftar.'}), 409

    user_model.create_user(username, email, no_hp, password)
    return jsonify({'status': 'success', 'message': 'Registrasi berhasil.'}), 201
