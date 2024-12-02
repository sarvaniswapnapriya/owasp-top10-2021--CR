from flask import Blueprint, render_template, request, current_app, render_template_string, session, redirect, url_for, flash
import os
from .models import User, db
from sqlalchemy import text
import subprocess
from hashlib import sha256
from cryptography.fernet import Fernet
from markupsafe import escape
from .forms import CommentForm, LoginForm, UploadForm
import logging
from datetime import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

failed_logins = []


# Konfiguracja e-maila
EMAIL_ADDRESS = ""
EMAIL_PASSWORD = ""
EMAIL_RECIPIENT = ""

def send_email(subject, body):
    msg = MIMEMultipart()
    msg['From'] = EMAIL_ADDRESS
    msg['To'] = EMAIL_RECIPIENT
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP('sandbox.smtp.mailtrap.io', 587) as server:
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        text = msg.as_string()
        server.sendmail(EMAIL_ADDRESS, EMAIL_RECIPIENT, text)


logging.basicConfig(filename='security.log', level=logging.INFO)

def log_event(event, details=""):
    logging.info(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {event} - {details}")

from collections import defaultdict

failed_login_attempts = defaultdict(int)

def log_failed_login(username):
    failed_logins.append({
        "username": username,
        "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    })
    log_event('LOGIN_FAILURE', f"User: {username}")
    failed_login_attempts[username] += 1

    if failed_login_attempts[username] == 5:
        subject = "Alert: Multiple Failed Login Attempts"
        body = f"There have been 5 failed login attempts for user {username}."
        send_email(subject, body)


comments = []


bp = Blueprint('main', __name__)

@bp.route('/')
def index():
    template_path = os.path.join(current_app.template_folder, 'index.html')
    return render_template_string(open(template_path).read())

@bp.route('/add_user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        new_user = User(username=username, email=email)
        db.session.add(new_user)
        db.session.commit()
        return 'User added!'
    template_path = os.path.join(current_app.template_folder, 'add_user.html')
    return render_template_string(open(template_path).read())

@bp.route('/users')
def users():
    users = User.query.all()
    users_list = ''.join([f'<li class="list-group-item">{user.username} - {user.email}</li>' for user in users])
    template = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>All Users</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <h1 class="mt-5">All Users</h1>
            <ul class="list-group mt-3">{users_list}</ul>
            <p class="mt-3"><a href="/" class="btn btn-secondary">Home</a></p>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrap.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </body>
    </html>
    '''
    return render_template_string(template)

@bp.route('/search_user', methods=['GET', 'POST'])
def search_user():
    if request.method == 'POST':
        username = request.form['username']
        query = text("SELECT * FROM user WHERE username = :username")
        result = db.session.execute(query, {"username": username})
        users = [f"<li class='list-group-item'>{row[1]} - {row[2]}</li>" for row in result]
        if not users:
            users_list = '<li class="list-group-item">No users found.</li>'
        else:
            users_list = ''.join(users)
        template = f'''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Search Results</title>
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="container">
                <h1 class="mt-5">Search Results</h1>
                <ul class="list-group mt-3">{users_list}</ul>
                <p class="mt-3"><a href='/search_user' class='btn btn-secondary'>Search Again</a></p>
                <p class="mt-3"><a href='/' class='btn btn-secondary'>Home</a></p>
            </div>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
            <script src="https://stackpath.bootstrap.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        </body>
        </html>
        '''
        return render_template_string(template)
    template_path = os.path.join(current_app.template_folder, 'search_user.html')
    return render_template_string(open(template_path).read())

@bp.route('/command', methods=['GET', 'POST'])
def command():
    output = None
    if request.method == 'POST':
        cmd = request.form['cmd']
        allowed_commands = ['ls', 'pwd', 'date']
        if cmd in allowed_commands:
            try:
                result = subprocess.run([cmd], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                output = result.stdout
            except subprocess.CalledProcessError as e:
                output = f"An error occurred: {e.stderr}"
        else:
            output = "Command not allowed."
    template_path = os.path.join(current_app.template_folder, 'command.html')
    return render_template_string(open(template_path).read(), output=output)

@bp.route('/admin')
def admin():
    if 'user' not in session or 'session_id' not in session:
        flash('You need to be logged in to view this page')
        return redirect(url_for('main.login'))

    expected_session_id = session.get('session_id')
    if not expected_session_id or session['user'] != 'admin':
        flash('Invalid session')
        return redirect(url_for('main.login'))

    users = User.query.all()
    users_list = ''.join([f'<li class="list-group-item">{user.username} - {user.email}</li>' for user in users])
    template = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Page</title>
        <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
    </head>
    <body>
        <div class="container">
            <h1 class="mt-5">Admin Page</h1>
            <ul class="list-group mt-3">{users_list}</ul>
            <p class="mt-3"><a href="/" class="btn btn-secondary">Home</a></p>
            <p class="mt-3"><a href="/logout" class="btn btn-danger">Logout</a></p>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrap.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </body>
    </html>
    '''
    return render_template_string(template)


from flask import Blueprint, render_template, request, flash, redirect, url_for, session
from werkzeug.security import check_password_hash, generate_password_hash


users = {
    "admin": generate_password_hash("password")
}

@bp.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = users.get(username)
        if user and check_password_hash(user, password):
            session['user'] = username
            flash('Logged in successfully.', 'success')
            log_event('LOGIN_SUCCESS', f"User: {username}")
            failed_login_attempts[username] = 0  # Reset failed attempts on successful login
            return redirect(url_for('main.index'))
        else:
            error = 'Invalid credentials'
            log_failed_login(username)
    template = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Login</title>
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="container mt-5">
                <h1 class="mb-4">Login</h1>
                {% if error %}
                <div class="alert alert-danger" role="alert">
                    {{ error }}
                </div>
                {% endif %}
                <form action="/login" method="POST">
                    <div class="form-group">
                        <label for="username">Username</label>
                        <input type="text" class="form-control" id="username" name="username" required>
                    </div>
                    <div class="form-group">
                        <label for="password">Password</label>
                        <input type="password" class="form-control" id="password" name="password" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Login</button>
                </form>
            </div>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
            <script src="https://stackpath.bootstrap.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        </body>
        </html>
    '''
    return render_template_string(template, error=error)

@bp.route('/logout')
def logout():
    username = session.get('user')
    session.pop('user', None)
    log_event('LOGOUT', f"User: {username}")
    flash('You were successfully logged out')
    return redirect(url_for('main.login'))


@bp.route('/change_password', methods=['GET', 'POST'])
def change_password():
    if 'user' not in session:
        flash('You need to be logged in to change your password')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        if session['user'] == 'admin' and current_password == 'password':
            flash('Password changed successfully')
            return redirect(url_for('main.admin'))
        else:
            flash('Current password is incorrect')
    template_path = os.path.join(current_app.template_folder, 'change_password.html')
    return render_template_string(open(template_path).read())

def write_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    return open("secret.key", "rb").read()

if not os.path.exists("secret.key"):
    write_key()

key = load_key()
cipher_suite = Fernet(key)

@bp.route('/store_data', methods=['GET', 'POST'])
def store_data():
    if request.method == 'POST':
        sensitive_data = request.form['data']
        key = load_key()
        flash(f'Encryption key: {key.decode()}')  # Dodaj to, aby wyświetlić klucz
        cipher_suite = Fernet(key)
        encrypted_data = cipher_suite.encrypt(sensitive_data.encode())
        with open('sensitive_data.txt', 'a') as f:
            f.write(f"{encrypted_data.decode()}\n")
        flash('Data stored securely!', 'success')
        return redirect(url_for('main.store_data'))
    template_path = os.path.join(current_app.template_folder, 'store_data.html')
    return render_template_string(open(template_path).read())




# Wygenerowanie klucza i zapisanie go do pliku
def write_key():
    key = Fernet.generate_key()
    with open("secret.key", "wb") as key_file:
        key_file.write(key)

# Wczytanie klucza z pliku
def load_key():
    return open("secret.key", "rb").read()

# Sprawdzenie, czy klucz istnieje, jeśli nie, to go tworzymy
if not os.path.exists("secret.key"):
    write_key()

key = load_key()
cipher_suite = Fernet(key)

@bp.route('/leak_key', methods=['GET'])
def leak_key():
    try:
        key = load_key().decode()
        flash(f'This is the leaked key: {key}', 'danger')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('main.index'))

@bp.route('/decrypt_data', methods=['GET'])
def decrypt_data():
    try:
        key = load_key()
        flash(f'Error decryption key!', 'danger')  # Dodaj to, aby wyświetlić klucz
        cipher_suite = Fernet(key)
        decrypted_data_list = []
        with open('sensitive_data.txt', 'r') as f:
            for line in f:
                encrypted_data = line.strip().encode()
                try:
                    decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
                    decrypted_data_list.append(decrypted_data)
                except Exception as e:
                    flash(f'Error decrypting data: {str(e)}', 'danger')
                    return redirect(url_for('main.index'))
        decrypted_data = "<br>".join(decrypted_data_list)
        flash(f'Decrypted data: {decrypted_data}', 'success')
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('main.index'))

from .forms import UpdateEmailForm

@bp.route('/update_email', methods=['GET', 'POST'])
def update_email():
    form = UpdateEmailForm()
    if form.validate_on_submit():
        new_email = form.email.data
        user = User.query.filter_by(username=session.get('user')).first()
        if user:
            user.email = new_email
            db.session.commit()
            flash('Email updated successfully', 'success')
        else:
            flash('User not found!', 'danger')
        return redirect(url_for('main.update_email'))
    template_path = os.path.join(current_app.template_folder, 'update_email.html')
    return render_template_string(open(template_path).read(), form=form)


@bp.route('/current_email', methods=['GET'])
def current_email():
    user = User.query.filter_by(username='admin').first()
    email = user.email if user else 'User not found!'
    template_path = os.path.join(current_app.template_folder, 'current_email.html')
    return render_template_string(open(template_path).read(), email=email)

@bp.route('/add_comment', methods=['GET', 'POST'])
def add_comment():
    form = CommentForm()
    if form.validate_on_submit():
        comment = escape(form.comment.data)  # Sanitizacja danych wejściowych
        username = session.get('user', 'Anonymous')
        comments.append({'username': username, 'comment': comment})
        flash('Comment added!', 'success')
        return redirect(url_for('main.view_comments'))
    template_path = os.path.join(current_app.template_folder, 'add_comment.html')
    return render_template_string(open(template_path).read(), form=form)

@bp.route('/view_comments')
def view_comments():
    comments_html = ''.join([f'<div class="comment-box"><strong>{escape(c["username"])}:</strong> {escape(c["comment"])}</div>' for c in comments])
    template = f'''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>View Comments</title>
        <link href="https://stackpath.bootstrap.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            .comment-box {{
                border: 1px solid #ccc;
                padding: 10px;
                margin: 10px 0;
                border-radius: 5px;
                background-color: #f9f9f9;
            }}
        </style>
    </head>
    <body>
        <div class="container mt-5">
            <h1 class="mb-4">Comments</h1>
            <div>{comments_html}</div>
            <a href="/" class="btn btn-primary mt-3">Home</a>
        </div>
        <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
        <script src="https://stackpath.bootstrap.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
    </body>
    </html>
    '''
    return render_template_string(template)



from flask import Blueprint, render_template, request, flash, redirect, url_for
import os
from werkzeug.utils import secure_filename
from PIL import Image
import imghdr


ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def validate_image(stream):
    header = stream.read(512)
    stream.seek(0)
    format = imghdr.what(None, header)
    if not format:
        return None
    return format if format in ALLOWED_EXTENSIONS else None

@bp.route('/upload', methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            
            if not os.path.exists('uploads'):
                os.makedirs('uploads')

            # Walidacja obrazu
            if validate_image(file.stream):
                file.save(os.path.join('uploads', filename))
                flash('File uploaded successfully', 'success')
                return redirect(url_for('main.index'))  # Przekierowanie na stronę główną
            else:
                flash('Invalid file content', 'danger')
                return redirect(url_for('main.upload'))
        else:
            flash('Invalid file type', 'danger')
            return redirect(url_for('main.upload'))
    return '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Upload File</title>
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="container mt-5">
                <h1 class="mb-4">Upload File</h1>
                <form action="/upload" method="POST" enctype="multipart/form-data">
                    <div class="form-group">
                        <label for="file">Choose file</label>
                        <input type="file" class="form-control" id="file" name="file">
                    </div>
                    <button type="submit" class="btn btn-primary">Upload</button>
                </form>
            </div>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
            <script src="https://stackpath.bootstrap.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        </body>
        </html>
    '''

import re
import requests
from urllib.parse import urlparse
from flask import Blueprint, render_template_string, request


def is_valid_url(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme not in ['http', 'https']:
        return False
    if parsed_url.hostname in ['localhost', '127.0.0.1']:
        return False
    return True

@bp.route('/fetch_url', methods=['GET', 'POST'])
def fetch_url():
    error = None
    content = None
    if request.method == 'POST':
        url = request.form['url']
        if not is_valid_url(url):
            error = "Nieprawidłowy URL"
        else:
            try:
                response = requests.get(url, timeout=5)
                response.raise_for_status()
                content = response.text
            except requests.RequestException as e:
                error = f"Błąd podczas pobierania URL: {e}"
    
    template = '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Pobierz URL</title>
            <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body>
            <div class="container mt-5">
                <h1 class="mb-4">Pobierz URL</h1>
                <form action="/fetch_url" method="POST">
                    <div class="form-group">
                        <label for="url">URL</label>
                        <input type="text" class="form-control" id="url" name="url" required>
                    </div>
                    <button type="submit" class="btn btn-primary">Pobierz</button>
                </form>
                {% if error %}
                <div class="alert alert-danger mt-3" role="alert">
                    {{ error }}
                </div>
                {% elif content %}
                <div class="alert alert-success mt-3" role="alert">
                    Pobrana zawartość:
                    <pre>{{ content }}</pre>
                </div>
                {% endif %}
            </div>
            <script src="https://code.jquery.com/jquery-3.5.1.slim.min.js"></script>
            <script src="https://cdn.jsdelivr.net/npm/@popperjs/core@2.9.2/dist/umd/popper.min.js"></script>
            <script src="https://stackpath.bootstrap.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        </body>
        </html>
    '''
    return render_template_string(template, error=error, content=content)








