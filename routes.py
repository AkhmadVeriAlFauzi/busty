from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from bson import ObjectId
from models.user import User
from pymongo import MongoClient
from werkzeug.security import check_password_hash, generate_password_hash
from flask_mail import Message
from extensions import mail, mongo
from models.user import User
from dotenv import load_dotenv
from imap_tools import MailBox, AND
from datetime import datetime, timedelta

import os
import re
import random
import bcrypt
import smtplib

# Load .env file
load_dotenv()
email_user = os.getenv('EMAIL_USER')
email_pass = os.getenv('EMAIL_PASS')


main = Blueprint('main', __name__)
client = MongoClient('mongodb+srv://user:OG2QqFuCYwkoWBek@capstone.fqvkpyn.mongodb.net/?retryWrites=true&w=majority')
db = client['busty_db']
dbcuaca = client['cuaca_db']
user_model = User(db)



auth = Blueprint('auth', __name__, url_prefix='/auth')

def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_email(email, otp, expiry_minutes=1):
    msg = Message('Kode OTP Busty Kamu', recipients=[email])
    msg.body = f'''
    Kode OTP kamu adalah: {otp}
    
    OTP ini hanya berlaku selama {expiry_minutes} menit.
    Jangan bagikan kode ini ke siapa pun.
    '''
    mail.send(msg)


def check_latest_email():
    with MailBox('imap.gmail.com').login(email_user, email_pass, 'INBOX') as mailbox:
        emails = list(mailbox.fetch(AND(seen=False), limit=1, reverse=True))
        if len(emails) == 0:
            return None
        return emails[0]

def extract_link(email_text):
    url_pattern = re.compile(r'https?://[^\s]+')
    match = url_pattern.search(email_text)
    if match:
        return match.group()
    return None

def extract_otp(email_text):
    otp_pattern = re.compile(r'\b\d{6}\b')
    match = otp_pattern.search(email_text)
    if match:
        return match.group()
    return None

@main.route('/')
def index():
    return render_template('index.html')

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Cari user berdasarkan email
        user = user_model.find_by_email(email)

        if not user:
            flash('Email tidak terdaftar.', 'danger')
            return redirect(url_for('auth.login'))
        
        if user and check_password_hash(user['password'], password):
        # Login berhasil
            session['user_id'] = str(user['_id'])
            session['username'] = user['username']
            flash(f'Selamat datang, {user["username"]}!', 'success')
            return redirect(url_for('main.dashboard'))
        else:
            flash('Password salah.', 'danger')
            return redirect(url_for('auth.login'))
        
    return render_template('auth/login.html')

@auth.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        no_hp = request.form['no_hp']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            flash('Password dan konfirmasi tidak sama.', 'danger')
            return redirect(url_for('auth.register'))

        # Simpan data ke session sementara
        otp = generate_otp()
        session['otp'] = otp
        session['otp_expired_at'] = (datetime.utcnow() + timedelta(minutes=1)).isoformat()  # ⏳ expired 5 menit
        session['user_temp'] = {
            'username': username,
            'email': email,
            'no_hp': no_hp,
            'password': generate_password_hash(password),
        }

        send_otp_email(email, otp, 1)  # kirim email + info expired


        flash('Kode OTP telah dikirim ke email kamu.', 'info')
        return redirect(url_for('auth.verify_otp'))

    return render_template('auth/register.html')


@auth.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        input_otp = request.form['otp']
        otp = session.get('otp')
        otp_expired_at = session.get('otp_expired_at')
        user_temp = session.get('user_temp')

        if not user_temp or not otp_expired_at:
            flash('Session expired. Silakan register ulang.', 'danger')
            return redirect(url_for('auth.register'))

        # Cek apakah OTP sudah expired
        expired_time = datetime.fromisoformat(otp_expired_at)
        if datetime.utcnow() > expired_time:
            flash('Kode OTP telah kedaluwarsa. Silakan klik "Kirim ulang OTP".', 'danger')
            return redirect(url_for('auth.verify_otp'))

        if input_otp == otp:
            user_model.create_user(
                user_temp['username'],
                user_temp['email'],
                user_temp['no_hp'],
                user_temp['password']
            )
            session.pop('otp', None)
            session.pop('otp_expired_at', None)
            session.pop('user_temp', None)

            flash('Registrasi berhasil. Silakan login.', 'success')
            return redirect(url_for('auth.login'))
        else:
            flash('OTP salah. Silakan coba lagi.', 'danger')

    return render_template('auth/verify_otp.html')

@auth.route('/resend-otp', methods=['POST'])
def resend_otp():
    user_temp = session.get('user_temp')
    if not user_temp:
        flash('Session expired. Silakan register ulang.', 'danger')
        return redirect(url_for('auth.register'))

    otp = generate_otp()
    session['otp'] = otp
    session['otp_expired_at'] = (datetime.utcnow() + timedelta(minutes=5)).isoformat()
    send_otp_email(user_temp['email'], otp)

    flash('Kode OTP baru telah dikirim ke email kamu. Berlaku selama 1 menit.', 'info')
    return redirect(url_for('auth.verify_otp'))


@auth.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        pass
    return render_template('auth/forgot_password.html')

@main.route('/dashboard')
def dashboard():
    return render_template('cms_page/dashboard.html')

# Route Pengguna

@main.route('/pengguna')
def list_pengguna():
    search_query = request.args.get('search', '').strip().lower()
    users = user_model.get_all_users()

    if search_query:
        users = [user for user in users if search_query in user.get('username', '').lower()]

    return render_template('cms_page/pengguna/user.html', users=users)

@main.route('/hapus-pengguna', methods=['POST'])
def hapus_pengguna():
    user_id = request.form.get('user_id')

    if user_id:
        try:
            deleted = user_model.delete_user_by_id(user_id)
            if deleted:
                flash("Pengguna berhasil dihapus.", "success")
            else:
                flash("Pengguna tidak ditemukan.", "error")
        except Exception as e:
            flash(f"Gagal menghapus pengguna: {e}", "error")
    else:
        flash("ID pengguna tidak valid.", "error")

    return redirect(url_for('main.list_pengguna'))

@main.route('/edit-pengguna/<user_id>')
def edit_pengguna(user_id):
    user = user_model.get_user_by_id(ObjectId(user_id))
    if not user:
        flash("Pengguna tidak ditemukan.", "error")
        return redirect(url_for('main.list_pengguna'))
    return render_template('cms_page/pengguna/edit_pengguna.html', user=user)


@main.route('/update-pengguna', methods=['POST'])
def update_pengguna():
    user_id = request.form.get('user_id')
    username = request.form.get('username')
    email = request.form.get('email')

    if not user_id or not username or not email:
        flash("Data tidak lengkap.", "error")
        return redirect(url_for('main.list_pengguna'))

    try:
        user_model.update_user(user_id, {
            "username": username,
            "email": email
        })
        flash("Pengguna berhasil diperbarui.", "success")
    except Exception as e:
        flash(f"Gagal memperbarui pengguna: {e}", "error")

    return redirect(url_for('main.list_pengguna'))



# Route Detail Cuaca

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
    
@main.route('/jadwal')
def jadwal():
    return render_template('cms_page/jadwal/jadwal.html')
    
@main.route('/rute')
def rute():
    return render_template('cms_page/rute/rute.html')

# Route Armada

@main.route('/armada')
def list_armada():
    search_nama = request.args.get('search_nama', '').lower()
    armada_data = list(db['armada'].find())

    # filter berdasarkan pencarian nama bus atau nopol
    if search_nama:
        armada_data = [
            item for item in armada_data
            if search_nama in item.get('nama_bus', '').lower() or
               search_nama in item.get('nopol', '').lower()
        ]

    return render_template('cms_page/armada/armada.html', armada_data=armada_data)


@main.route('/tambah-armada', methods=['GET', 'POST'])
def tambah_armada():
    if request.method == 'POST':
        nopol = request.form.get('nopol')
        nama_bus = request.form.get('nama_bus')
        status = request.form.get('status')
        detail_status = request.form.get('detail_status')

        if not all([nopol, nama_bus, status]):
            flash("Harap isi semua data yang diperlukan.", "error")
            return redirect(url_for('main.tambah_armada'))

        # Simpan ke MongoDB
        db['armada'].insert_one({
            'nopol': nopol,
            'nama_bus': nama_bus,
            'status': status,
            'detail_status': detail_status,
            'created_at': datetime.utcnow()
        })

        flash("Data armada berhasil ditambahkan.", "success")
        return redirect(url_for('main.list_armada'))  # Ganti ke route list kalau ada

    return render_template('cms_page/armada/tambah_armada.html')

@main.route('/hapus-armada', methods=['POST'])
def hapus_armada():
    armada_id = request.form.get('armada_id')
    if armada_id:
        try:
            db['armada'].delete_one({'_id': ObjectId(armada_id)})
            flash("Armada berhasil dihapus.", "success")
        except Exception as e:
            flash(f"Gagal menghapus armada: {e}", "danger")
    else:
        flash("ID armada tidak valid.", "danger")
    return redirect(url_for('main.list_armada'))

@main.route('/cms/edit-armada/<armada_id>', methods=['GET'])
def edit_armada(armada_id):
    armada_data = mongo.db.armada.find_one({'_id': ObjectId(armada_id)})
    return render_template('cms_page/armada/edit_armada.html', armada_data=armada_data)


@main.route('/update-armada', methods=['POST'])
def update_armada():
    armada_id = request.form.get('armada_id')
    nopol = request.form.get('nopol')
    nama_bus = request.form.get('nama_bus')
    status = request.form.get('status')
    detail_status = request.form.get('detail_status')

    if not armada_id or not nopol or not nama_bus or not status:
        flash("Data tidak lengkap.", "danger")
        return redirect(url_for('main.list_armada'))

    try:
        db['armada'].update_one(
            {'_id': ObjectId(armada_id)},
            {'$set': {
                'nopol': nopol,
                'nama_bus': nama_bus,
                'status': status,
                'detail_status': detail_status,
                'updated_at': datetime.utcnow()
            }}
        )
        flash("Data armada berhasil diperbarui.", "success")
    except Exception as e:
        flash(f"Gagal update armada: {e}", "danger")

    return redirect(url_for('main.list_armada'))




@main.route('/artikel')
def artikel():
    return render_template('cms_page/artikel/artikel.html')

@auth.route('/logout')
def logout():
    return redirect(url_for('auth.login'))