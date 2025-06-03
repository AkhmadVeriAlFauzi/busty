from flask import Blueprint, request, jsonify, session
from routes import generate_otp, send_otp_email
from werkzeug.security import generate_password_hash
from models.user import User
from pymongo import MongoClient
from werkzeug.security import check_password_hash
import jwt
from functools import wraps
from bson import ObjectId
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()  # Baca isi file .env

API_KEY = os.getenv('API_KEY')

api = Blueprint('api', __name__, url_prefix='/api')
client = MongoClient('mongodb+srv://user:OG2QqFuCYwkoWBek@capstone.fqvkpyn.mongodb.net/?retryWrites=true&w=majority')
db = client['busty_db']
dbcuaca = client['cuaca_db']
user_model = User(db)
SECRET_KEY = 'busty_secret_key'


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Cek API Key
        api_key = request.headers.get('x-api-key')
        if not api_key or api_key != API_KEY:
            return jsonify({'error': 'Unauthorized - Invalid or missing API key'}), 401

        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Unauthorized - Missing or invalid token'}), 401

        token = auth_header.split(' ')[1]
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = payload['user_id']  # Bisa dipakai di route
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401

        return f(*args, **kwargs)
    return decorated

@api.route('/protected', methods=['GET'])
@require_auth
def protected_route(current_user):
    
    """
    Endpoint Terproteksi (Memerlukan API Key dan Token JWT)
    ---
    tags:
      - Auth
    security:
      - ApiKeyAuth: []
      - BearerAuth: []
    responses:
      200:
        description: Akses berhasil, data user dikembalikan
        schema:
          type: object
          properties:
            message:
              type: string
              example: Berhasil mengakses endpoint terlindungi!
            user:
              type: object
              properties:
                id:
                  type: string
                username:
                  type: string
                email:
                  type: string
      401:
        description: Token atau API Key tidak valid
    """
    
    return jsonify({
        'message': 'Berhasil mengakses endpoint terlindungi!',
        'user': {
            'id': str(current_user['_id']),
            'username': current_user['username'],
            'email': current_user['email']
        }
    })


# api register

@api.route('/register', methods=['POST'])
def api_register():
    """
    Register a new user and send OTP to their email.

    Expected JSON body:
    {
        "username": "string",
        "email": "string",
        "no_hp": "string",
        "password": "string"
    }

    Returns:
        200 OK: OTP has been sent to the user's email.
        400 Bad Request: Missing required fields.
        409 Conflict: Email or username already exists.
    """
    
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

    hashed_password = generate_password_hash(password)
    otp = generate_otp()

    user_data = {
        'username': username,
        'email': email,
        'no_hp': no_hp,
        'password': hashed_password,
        'created_at': datetime.utcnow(),
        'is_verified': False,
        'otp': otp,
        'otp_expired': datetime.utcnow() + timedelta(minutes=1)
    }

    db.user.insert_one(user_data)

    session['otp'] = otp
    session['email'] = email

    send_otp_email(email, otp, expiry_minutes=5)

    return jsonify({'status': 'pending', 'message': 'OTP telah dikirim ke email kamu.'}), 200


@api.route('/verify-otp', methods=['POST'])
def api_verify_otp():
  
    """
    Verify user's account using the OTP sent to their email.

    Expected JSON body:
    {
        "otp": "string"
    }

    Session data must include:
        - email: the registered email address

    Returns:
        200 OK: Account successfully verified.
        400 Bad Request: Missing OTP/email, wrong OTP, or expired OTP.
        404 Not Found: User not found.
    """
    
    data = request.get_json()
    input_otp = data.get('otp')
    email = session.get('email')

    if not input_otp or not email:
        return jsonify({'status': 'error', 'message': 'OTP dan email wajib.'}), 400

    user = db.user.find_one({'email': email})

    if not user:
        return jsonify({'status': 'error', 'message': 'User tidak ditemukan.'}), 404

    if user['is_verified']:
        return jsonify({'status': 'error', 'message': 'Akun sudah terverifikasi.'}), 400

    if input_otp != user.get('otp'):
        return jsonify({'status': 'error', 'message': 'OTP salah.'}), 400

    if datetime.utcnow() > user.get('otp_expired', datetime.utcnow()):
        return jsonify({'status': 'error', 'message': 'OTP sudah kedaluwarsa.'}), 400

    db.user.update_one({'email': email}, {
        '$set': {'is_verified': True},
        '$unset': {'otp': "", 'otp_expired': ""}
    })

    session.pop('otp', None)
    session.pop('email', None)

    return jsonify({'status': 'success', 'message': 'Akun berhasil diverifikasi.'}), 200


@api.route('/resend-otp', methods=['POST'])
def resend_otp():

    """
    Resend a new OTP to the user's email if not yet verified.

    Expected JSON body:
    {
        "email": "string"
    }

    Returns:
        200 OK: New OTP sent successfully.
        400 Bad Request: Email is missing or account is already verified.
        404 Not Found: User with the provided email does not exist.
    """
    
    data = request.get_json()
    email = data.get('email')
    if not email:
        return jsonify({'status': 'error', 'message': 'Email wajib diisi.'}), 400

    user = db.user.find_one({'email': email})
    if not user:
        return jsonify({'status': 'error', 'message': 'User tidak ditemukan.'}), 404

    if user['is_verified']:
        return jsonify({'status': 'error', 'message': 'Akun sudah terverifikasi.'}), 400

    new_otp = generate_otp()
    db.user.update_one({'email': email}, {
        '$set': {
            'otp': new_otp,
            'otp_expired': datetime.utcnow() + timedelta(minutes=5)
        }
    })
    send_otp_email(email, new_otp, expiry_minutes=5)
    return jsonify({'status': 'success', 'message': 'OTP baru telah dikirim.'}), 200


@api.route('/login', methods=['POST'])
def api_login():
    
    """
    Login user dan dapatkan token JWT
    ---
    tags:
      - Auth
    parameters:
      - in: body
        name: body
        required: true
        schema:
          id: LoginUser
          required:
            - email
            - password
          properties:
            email:
              type: string
              example: niko@example.com
            password:
              type: string
              example: secret123
    responses:
      200:
        description: Login berhasil, kembalikan token JWT
        schema:
          type: object
          properties:
            status:
              type: string
            token:
              type: string
      401:
        description: Email atau password salah     
    """
    
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = user_model.find_by_email(email)

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'status': 'error', 'message': 'Email atau password salah.'}), 401

    payload = {
        'user_id': str(user['_id']),
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")

    return jsonify({'status': 'success', 'token': token}), 200


@api.route('/data-cuaca', methods=['GET'])
@require_auth
def get_data_cuaca():
    
    """
    Ambil data prakiraan cuaca (auth required)
    ---
    tags:
      - Cuaca
    parameters:
      - name: search_daerah
        in: query
        type: string
        required: false
        description: Nama kab/kota, kecamatan, atau kelurahan untuk filter pencarian
    security:
      - ApiKeyAuth: []
      - BearerAuth: []
    responses:
      200:
        description: Daftar data cuaca
        schema:
          type: array
          items:
            type: object
            properties:
              _id:
                type: string
              kab_kota:
                type: string
              kecamatan:
                type: string
              kelurahan:
                type: string
              suhu:
                type: integer
      401:
        description: Token atau API Key tidak valid
    """
    
    search = request.args.get('search_daerah', '').lower()
    cuaca_data = list(dbcuaca['prakiraan_cuaca'].find())

    for data in cuaca_data:
        data['_id'] = str(data['_id'])
        data['suhu'] = int(data['suhu'].split()[0])

    if search:
        cuaca_data = [
            data for data in cuaca_data
            if search in data.get('kab_kota', '').lower() 
            or search in data.get('kecamatan', '').lower()
            or search in data.get('kelurahan', '').lower()
        ]

    return jsonify(cuaca_data), 200

