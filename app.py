from flask import Flask, request, render_template, redirect, url_for, flash, session, jsonify
import sqlite3
from bcrypt import hashpw, gensalt, checkpw
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import secrets
import random
import time
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

OTP_EXPIRATION_TIME = 300  # 5 minutes
MAX_LOGIN_ATTEMPTS = 5
login_attempts = {}

# SMTP Email Configuration
EMAIL_ADDRESS = 'i212699@nu.edu.pk'
EMAIL_PASSWORD = 'chiy ehjc hmoz tkxz'

serializer = URLSafeTimedSerializer(app.secret_key)  # Serializer for generating and verifying tokens


def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP('smtp.gmail.com', 587) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.ehlo()
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
            print(f'Email sent to {to_email}!')
    except Exception as e:
        print(f'Failed to send email: {e}')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')
        email = request.form['email']

        hashed_pw = hashpw(password, gensalt())
        verification_token = serializer.dumps(email, salt='email-confirm')

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute(
                'INSERT INTO users (username, password, email, email_verified, verification_token) VALUES (?, ?, ?, ?, ?)',
                (username, hashed_pw, email, False, verification_token)
            )
            conn.commit()
            verification_url = url_for('confirm_email', token=verification_token, _external=True)
            email_body = f"Dear User,\n\nPlease verify your email address by clicking the link below:\n\n{verification_url}\n\nBest regards,\nYour Team"
            send_email(email, 'Verify Your Email Address', email_body)
            flash('A verification email has been sent. Please check your inbox.', 'info')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username or Email already exists!', 'danger')
        finally:
            conn.close()

    return render_template('register.html')


@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = serializer.loads(token, salt='email-confirm', max_age=86400)
        conn = sqlite3.connect('users.db')
        cursor = conn.cursor()
        cursor.execute(
            'UPDATE users SET email_verified = 1, verification_token = NULL WHERE email = ?',
            (email,)
        )
        conn.commit()
        flash('Your email has been verified! You can now log in.', 'success')
        return redirect(url_for('login'))
    except Exception as e:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('register'))
    finally:
        conn.close()


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password'].encode('utf-8')

        if username in login_attempts and login_attempts[username] >= MAX_LOGIN_ATTEMPTS:
            flash("Maximum login attempts exceeded. Please try again later.", 'danger')
            return redirect(url_for('login'))

        try:
            conn = sqlite3.connect('users.db')
            cursor = conn.cursor()
            cursor.execute('SELECT password, email_verified, email FROM users WHERE username = ?', (username,))
            user = cursor.fetchone()

            if user and checkpw(password, user[0]):
                if user[1]:
                    otp = random.randint(100000, 999999)
                    session['otp'] = otp
                    session['otp_timestamp'] = time.time()
                    session['email'] = user[2]
                    session['username'] = username
                    send_email(user[2], 'Your OTP', f"Your OTP is: {otp}")
                    flash('An OTP has been sent to your registered email. Please enter it below.', 'info')
                    return redirect(url_for('verify_otp'))
                else:
                    flash('Please verify your email before logging in.', 'danger')
            else:
                login_attempts[username] = login_attempts.get(username, 0) + 1
                flash('Invalid username or password.', 'danger')
        except sqlite3.Error as e:
            flash(f"An error occurred: {e}", 'danger')
        finally:
            conn.close()

    return render_template('login.html')


@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if request.method == 'POST':
        user_otp = request.form['otp']
        otp = session.get('otp')
        otp_timestamp = session.get('otp_timestamp')

        if otp and otp_timestamp:
            current_time = time.time()
            if current_time - otp_timestamp > OTP_EXPIRATION_TIME:
                flash('OTP has expired. Please try logging in again.', 'danger')
                session.pop('otp', None)
                session.pop('otp_timestamp', None)
                return redirect(url_for('login'))

            if str(otp) == user_otp:
                session.pop('otp', None)
                session.pop('otp_timestamp', None)
                flash('Login successful!', 'success')
                return redirect(url_for('main'))
            else:
                flash('Invalid OTP. Please try again.', 'danger')
        else:
            flash('Invalid request or session expired.', 'danger')

    return render_template('verify_otp.html')


@app.route('/resend_otp')
def resend_otp():
    otp = random.randint(100000, 999999)
    otp_timestamp = time.time()

    session['otp'] = otp
    session['otp_timestamp'] = otp_timestamp

    send_email(session['email'], 'Your OTP', f"Your OTP is: {otp}")
    flash('A new OTP has been sent to your email.', 'info')
    return redirect(url_for('verify_otp'))


@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/')
def main():
    return render_template('main.html')


if __name__ == '__main__':
    app.run(debug=True)