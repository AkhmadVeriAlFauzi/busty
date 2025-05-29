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

@main.route('/pengguna')
def pengguna():
    search_query = request.args.get('search', '').strip().lower()
    users = user_model.get_all_users()

    if search_query:
        users = [user for user in users if search_query in user.get('username', '').lower()]

    return render_template('cms_page/user.html', users=users)

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
    
@main.route('/rute')
def rute():
    return render_template('cms_page/rute.html')

@main.route('/armada')
def armada():
    return render_template('cms_page/armada.html')

@main.route('/artikel')
def artikel():
    return render_template('cms_page/artikel.html')

@main.route('/jadwal')
def jadwal():
    return render_template('cms_page/jadwal.html')


@auth.route('/logout')
def logout():
    return redirect(url_for('auth.login'))