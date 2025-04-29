from datetime import datetime
from werkzeug.security import generate_password_hash

class User:
    def __init__(self, db):
        self.collection = db['user']  # Nama koleksi MongoDB lu (users)

    def create_user(self, username, email, no_hp, password):
        hashed_password = generate_password_hash(password)
        user_data = {
            'username': username,
            'email': email,
            'no_hp': no_hp,
            'password': hashed_password,
            'created_at': datetime.utcnow()
        }
        return self.collection.insert_one(user_data)

    def find_by_email(self, email):
        return self.collection.find_one({'email': email})

    def find_by_username(self, username):
        return self.collection.find_one({'username': username})
