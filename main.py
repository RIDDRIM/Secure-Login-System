from flask import Flask, render_template_string, request, redirect, session, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re
import pyotp
import qrcode
import os

# ============================================
# FLASK APP CONFIGURATION
# ============================================

app = Flask(__name__)

app.config['SECRET_KEY'] = 'super_secret_key'

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ============================================
# DATABASE MODEL
# ============================================

class User(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(100), unique=True, nullable=False)

    password = db.Column(db.String(300), nullable=False)

    secret = db.Column(db.String(100), nullable=False)

# ============================================
# CREATE DATABASE
# ============================================

with app.app_context():
    db.create_all()

# ============================================
# INPUT VALIDATION
# ============================================

def validate_input(username, password):

    if len(username) < 4:
        return "Username must be at least 4 characters"

    if len(password) < 6:
        return "Password must be at least 6 characters"

    if not re.match("^[a-zA-Z0-9_]+$", username):
        return "Username can contain only letters, numbers, and underscore"

    return None

# ============================================
# HOME PAGE
# ============================================

@app.route('/')
def home():

    if 'user' in session:
        return f"""
        <h2>Welcome {session['user']}</h2>
        <a href='/logout'>Logout</a>
        """

    return """
    <h2>Secure Login System</h2>
    <a href='/register'>Register</a><br><br>
    <a href='/login'>Login</a>
    """

# ============================================
# REGISTER
# ============================================

@app.route('/register', methods=['GET', 'POST'])
def register():

    if request.method == 'POST':

        username = request.form['username']

        password = request.form['password']

        # Input Validation
        error = validate_input(username, password)

        if error:
            return f"<h3>{error}</h3>"

        # Check existing user
        existing_user = User.query.filter_by(username=username).first()

        if existing_user:
            return "<h3>User already exists</h3>"

        # Hash Password
        hashed_password = generate_password_hash(password)

        # Generate 2FA Secret
        secret = pyotp.random_base32()

        # Save User
        new_user = User(
            username=username,
            password=hashed_password,
            secret=secret
        )

        db.session.add(new_user)

        db.session.commit()

        # QR Code for Google Authenticator
        otp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="SecureLoginApp"
        )

        img = qrcode.make(otp_uri)

        img.save("static/qrcode.png")

        return """
        <h2>Registration Successful</h2>
        <p>Scan QR code using Google Authenticator</p>
        <img src='/static/qrcode.png' width='250'>
        <br><br>
        <a href='/login'>Go to Login</a>
        """

    return """
    <h2>Register</h2>

    <form method='POST'>

        Username:<br>
        <input type='text' name='username'><br><br>

        Password:<br>
        <input type='password' name='password'><br><br>

        <input type='submit' value='Register'>

    </form>
    """

# ============================================
# LOGIN
# ============================================

@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']

        password = request.form['password']

        otp = request.form['otp']

        # SQL Injection Protection:
        # SQLAlchemy ORM automatically parameterizes queries

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):

            # Verify OTP
            totp = pyotp.TOTP(user.secret)

            if totp.verify(otp):

                session['user'] = username

                return redirect(url_for('home'))

            else:
                return "<h3>Invalid OTP</h3>"

        else:
            return "<h3>Invalid Username or Password</h3>"

    return """
    <h2>Login</h2>

    <form method='POST'>

        Username:<br>
        <input type='text' name='username'><br><br>

        Password:<br>
        <input type='password' name='password'><br><br>

        OTP Code:<br>
        <input type='text' name='otp'><br><br>

        <input type='submit' value='Login'>

    </form>
    """

# ============================================
# LOGOUT
# ============================================

@app.route('/logout')
def logout():

    session.pop('user', None)

    return redirect(url_for('home'))

# ============================================
# RUN APP
# ============================================

if __name__ == '__main__':

    if not os.path.exists("static"):
        os.makedirs("static")

    app.run(debug=True)
