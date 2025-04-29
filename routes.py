from flask import Blueprint, render_template, request, redirect, url_for, flash
from models.user import User
from pymongo import MongoClient

# Blueprint untuk halaman utama (main)
main = Blueprint('main', __name__)

# Koneksi MongoDB
client = MongoClient('mongodb+srv://user:OG2QqFuCYwkoWBek@capstone.fqvkpyn.mongodb.net/?retryWrites=true&w=majority')
db = client['busty_db']  # Ganti sesuai nama database lu
user_model = User(db)

# Blueprint untuk halaman autentikasi (auth)
auth = Blueprint('auth', __name__, url_prefix='/auth')

# Landing page
@main.route('/')
def index():
    return render_template('index.html')

# Halaman login
@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Implementasikan logika login di sini
        pass
    return render_template('auth/login.html')

# Halaman register
@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        no_hp = request.form.get('no_hp')
        password = request.form.get('password')

        # Cek kalau email atau username sudah ada
        if user_model.find_by_email(email):
            flash('Email sudah terdaftar.', 'danger')
            return redirect(url_for('auth.register'))
        
        if user_model.find_by_username(username):
            flash('Username sudah terdaftar.', 'danger')
            return redirect(url_for('auth.register'))

        # Simpan user baru
        user_model.create_user(username, email, no_hp, password)
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')

# Halaman forgot password
@auth.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        # Implementasikan logika forgot password di sini
        pass
    return render_template('auth/forgot_password.html')

# CMS pages
@main.route('/dashboard')
def dashboard():
    return render_template('cms_page/dashboard.html')

@main.route('/admin/posts')
def post_list():
    return render_template('cms_page/post_list.html')

@main.route('/admin/editor')
def editor():
    return render_template('cms_page/editor.html')

@main.route('/settings')
def settings():
    return render_template('cms_page/settings.html')

@auth.route('/logout')
def logout():
    # Logika logout di sini, misalnya menghapus session atau token
    return redirect(url_for('auth.login'))

