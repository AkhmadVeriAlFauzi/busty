from flask import Blueprint, render_template, request, redirect, url_for, flash
from models.user import User
from pymongo import MongoClient
from werkzeug.security import check_password_hash

main = Blueprint('main', __name__)
client = MongoClient('mongodb+srv://user:OG2QqFuCYwkoWBek@capstone.fqvkpyn.mongodb.net/?retryWrites=true&w=majority')
db = client['busty_db']
dbcuaca = client['cuaca_db']
user_model = User(db)

auth = Blueprint('auth', __name__, url_prefix='/auth')

@main.route('/')
def index():
    return render_template('index.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = user_model.find_by_email(email)
        if user and check_password_hash(user['password'], password):
            flash('Login berhasil!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Email atau password salah.', 'danger')
            return redirect(url_for('auth.login'))

    return render_template('auth/login.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        no_hp = request.form.get('no_hp')
        password = request.form.get('password')

        if user_model.find_by_email(email):
            flash('Email sudah terdaftar.', 'danger')
            return redirect(url_for('auth.register'))
        if user_model.find_by_username(username):
            flash('Username sudah terdaftar.', 'danger')
            return redirect(url_for('auth.register'))

        user_model.create_user(username, email, no_hp, password)
        flash('Registrasi berhasil! Silakan login.', 'success')
        return redirect(url_for('auth.login'))

    return render_template('auth/register.html')

@auth.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        pass
    return render_template('auth/forgot_password.html')

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
    return redirect(url_for('auth.login'))

@main.route('/detail-cuaca')
def detail_cuaca():
    kecamatan_filter = request.args.get('kecamatan')
    cuaca_data = list(dbcuaca['prakiraan_cuaca_uji'].find())

    # Bersihin suhu: dari "26 °C" jadi 26 (int)
    for item in cuaca_data:
        item['suhu'] = int(item['suhu'].split()[0])

    # List kecamatan unik buat dropdown
    kecamatan_list = sorted(set(item['kecamatan'] for item in cuaca_data))

    # Filter berdasarkan kecamatan kalau dipilih
    if kecamatan_filter:
        cuaca_data = [item for item in cuaca_data if item['kecamatan'] == kecamatan_filter]

    return render_template('cms_page/detail_cuaca.html', cuaca_data=cuaca_data, kecamatan_list=kecamatan_list, selected_kecamatan=kecamatan_filter)


