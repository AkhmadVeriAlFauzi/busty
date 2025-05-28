import random
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from bson import ObjectId
from werkzeug.security import generate_password_hash

class User:
    def __init__(self, db):
        self.collection = db['user']

    def create_user(self, username, email, no_hp, password):
        # hashed_password = generate_password_hash(password)
        user_data = {
            'username': username,
            'email': email,
            'no_hp': no_hp,
            'password': password,
            'created_at': datetime.utcnow(),
            # 'is_verified': False  # default belum verifikasi
        }
        return self.collection.insert_one(user_data)

    def find_by_email(self, email):
        return self.collection.find_one({'email': email})

    def find_by_username(self, username):
        return self.collection.find_one({'username': username})

    def find_by_id(self, user_id):
        return self.collection.find_one({'_id': ObjectId(user_id)})
    
    def get_all_users(self):
        return list(self.collection.find())

    def set_otp(self, email, otp, expired_at):
        return self.collection.update_one(
            {'email': email},
            {'$set': {'otp': otp, 'otp_expired': expired_at, 'is_verified': False}}
        )

    def verify_otp(self, email, otp):
        user = self.find_by_email(email)
        if not user:
            return False, "User tidak ditemukan"
        if user.get('otp') != otp:
            return False, "Kode OTP salah"
        if datetime.utcnow() > user.get('otp_expired', datetime.utcnow()):
            return False, "Kode OTP sudah expired"
        # Update user jadi verified
        self.collection.update_one(
            {'email': email},
            {'$set': {'is_verified': True}, '$unset': {'otp': '', 'otp_expired': ''}}
        )
        return True, "Verifikasi berhasil"
