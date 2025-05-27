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

@main.route('/pengguna')
def pengguna():
    search_query = request.args.get('search', '').strip().lower()
    users = user_model.get_all_users()

    if search_query:
        users = [user for user in users if search_query in user.get('username', '').lower()]

    return render_template('cms_page/user.html', users=users)


@auth.route('/logout')
def logout():
    return redirect(url_for('auth.login'))

@main.route('/detail-cuaca')
def detail_cuaca():
    mode = request.args.get('mode', 'card')
    search_daerah = request.args.get('search_daerah', '').lower()
    
    # Ambil semua data dari MongoDB
    cuaca_data = list(dbcuaca['prakiraan_cuaca'].find())

    # Parsing suhu + handle error kalau formatnya aneh
    for item in cuaca_data:
        suhu_str = item.get('suhu', '0')
        try:
            # Ambil angka pertama dari suhu
            item['suhu'] = int(suhu_str.split()[0])
        except:
            item['suhu'] = 0  # Default ke 0 kalau gagal parsing
            
        item['cuaca'] = item.get('cuaca', 'Tidak diketahui')    

    # Filter data berdasarkan input search
    if search_daerah:
        cuaca_data = [
            item for item in cuaca_data
            if search_daerah in (item.get('provinsi') or '').lower()
            or search_daerah in (item.get('kab_kota') or '').lower()
            or search_daerah in (item.get('kecamatan') or '').lower()
            or search_daerah in (item.get('kelurahan') or '').lower()
        ]

    return render_template(
        'cms_page/detail_cuaca.html',
        cuaca_data=cuaca_data,
        mode=mode,
        search_daerah=search_daerah
    )
