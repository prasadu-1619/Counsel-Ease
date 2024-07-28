from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import random
import string
from flask_mail import Mail, Message
import pyotp
import datetime
import time
import os
import sys
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import base64
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
from urllib.parse import quote_plus as url_quote

appointment_list=[]
app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'counselease.pict@gmail.com'  # Update with your Gmail address
app.config['MAIL_PASSWORD'] = 'adjj tpog cwik twod'  # Update with your Gmail app password
app.config['MAIL_DEFAULT_SENDER'] = 'counselease.pict@gmail.com'

mail = Mail(app)

# Define the scopes required for Google API
SCOPES = ['https://www.googleapis.com/auth/calendar',
          'https://www.googleapis.com/auth/gmail.send']

# Function to authenticate Google API
def authenticate_google():
    creds = None

    # Check if token.json exists and if it's valid
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json')

    # If token is invalid or expired, reauthorize
    if not creds or not creds.valid:
        # Remove existing token file
        if os.path.exists('token.json'):
            os.remove('token.json')
        
        # Run the OAuth flow to obtain new credentials
        flow = InstalledAppFlow.from_client_secrets_file(
            'credentials.json', SCOPES)
        creds = flow.run_local_server(port=0)

        # Save the new credentials to token.json
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    return creds

# Obtain Google credentials
creds = authenticate_google()


# Function to create a connection to the SQLite database
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Generate a random secret key for OTP
def generate_otp_secret():
    return pyotp.random_base32()

# Generate and send OTP via email
def send_otp_email(email, otp):
    msg = Message('OTP Verification', recipients=[email])
    msg.subject = 'Email Verification'
    msg.sender = "Counsel Ease"
    msg.body = f'Your OTP for verification is: {otp}'
    mail.send(msg)

# Function to create a Google Meet link
def create_meet_link(creds):
    service = build('calendar', 'v3', credentials=creds)
    event = {
        'summary': 'Meeting',
        'description': 'Meeting via Google Meet',
        'start': {
            'dateTime': (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
            'timeZone': 'UTC',
        },
        'end': {
            'dateTime': (datetime.datetime.now() + datetime.timedelta(minutes=10)).isoformat(),
            'timeZone': 'UTC',
        },
        'conferenceData': {
            'createRequest': {
                'requestId': 'meetlink'
            }
        }
    }

    try:
        event = service.events().insert(calendarId='primary', body=event, conferenceDataVersion=1).execute()
        return event.get('hangoutLink')
    except HttpError as err:
        print(f'An error occurred: {err}')
        return None

# Function to handle the signup process
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        conn = get_db_connection()
        cur = conn.cursor()
        firstName = request.form['firstName']
        lastName = request.form['lastName']
        phoneNumber = request.form['phoneNumber']
        email = request.form['email']
        password = request.form['password']
        collegeName = request.form['collegeName']
        collegeRegNo = request.form['collegeRegNo']
        
        # Generate and store OTP secret key for the user
        otp_secret = generate_otp_secret()
        session['otp_secret'] = otp_secret
        
        # Generate OTP
        totp = pyotp.TOTP(otp_secret)
        otp = totp.now()
        
        # Send OTP via email
        send_otp_email(email, otp)
        
        cur.execute('INSERT INTO users (firstName, lastName, phoneNumber, email, password, collegeName, collegeRegNo, otp_secret) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                    (firstName, lastName, phoneNumber, email, password, collegeName, collegeRegNo, otp_secret))
        conn.commit()
        conn.close()
        flash('A verification code has been sent to your email.', 'success')
        return redirect(url_for('verify_otp'))
    return render_template('signup.html')

# Function to verify OTP
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    if 'otp_secret' not in session:
        flash('Invalid verification attempt.', 'error')
        return redirect(url_for('signup'))

    if request.method == 'POST':
        otp_attempt = request.form['otp']
        otp_secret = session['otp_secret']
        totp = pyotp.TOTP(otp_secret)
        generated_otp = totp.now()
        app.logger.debug("Generated OTP: %s", generated_otp)  # Debugging
        app.logger.debug("Entered OTP: %s", otp_attempt)      # Debugging
        if totp.verify(otp_attempt):
            flash('OTP verification successful!', 'success')
            session.pop('otp_secret')
            return redirect(url_for('login'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
            return redirect(url_for('login'))

    return render_template('verify_otp.html')

# Function to send reset password email
def send_reset_email(email, reset_link):
    msg = Message('Password Reset Request', recipients=[email])
    msg.body = f'To reset your password, visit the following link: {reset_link}'
    mail.send(msg)

# Function to handle the login process
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        conn = get_db_connection()
        cur = conn.cursor()
        email = request.form['email']
        password = request.form['password']
        cur.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cur.fetchone()
        conn.close()
        if user and user['password'] == password:
            session['user'] = user['id']
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid email or password. Please try again.'
    return render_template('login.html', error=error)

# Function to handle the home page
@app.route('/')
def home():
    return render_template('home.html')

# Function to handle the dashboard
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    else:
        user_id = session['user']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT firstName, lastName, email FROM users WHERE id = ?', (user_id,))
        user_info = cur.fetchone()
        conn.close()
        if user_info:
            first_name = user_info['firstName']
            last_name = user_info['lastName']
            email = user_info['email']
            return render_template('dashboard.html', first_name=first_name, last_name=last_name, email=email)
        else:
            flash('User information not found.', 'error')
            return redirect(url_for('login'))

# Function to handle the logout process
@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('home'))

# Function to generate a meeting link

def generate_meeting_link(creds):
    service = build('calendar', 'v3', credentials=creds)
    event = {
        'summary': 'Meeting',
        'description': 'Meeting via Google Meet',
        'start': {
            'dateTime': (datetime.datetime.now() + datetime.timedelta(minutes=5)).isoformat(),
            'timeZone': 'UTC',
        },
        'end': {
            'dateTime': (datetime.datetime.now() + datetime.timedelta(minutes=10)).isoformat(),
            'timeZone': 'UTC',
        },
        'conferenceData': {
            'createRequest': {
                'requestId': 'meetlink'
            }
        }
    }

    try:
        event = service.events().insert(calendarId='primary', body=event, conferenceDataVersion=1).execute()
        return event.get('hangoutLink')
    except HttpError as err:
        print(f'An error occurred: {err}')
        return None

# Route for booking an appointment
@app.route('/book_appointment', methods=['POST'])
def book_appointment():
    if request.method == 'POST':
        if 'user' in session:
            user_id = session['user']
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('SELECT firstName, lastName, email, phoneNumber,collegeName,collegeRegNo FROM users WHERE id = ?', (user_id,))
            user_info = cur.fetchone()
            conn.close()
            if user_info:
                first_name = user_info['firstName']
                last_name = user_info['lastName']
                email = user_info['email']
                phone_number = user_info['phoneNumber']
                college_name = user_info['collegeName']
                college_reg_no = user_info['collegeRegNo']
                date = request.form['date']
                time = request.form['time']
                counselor = request.form['counselor']
                
                # Check if the chosen slot is already booked for the counselor
                for appointment in appointment_list:
                    if (appointment['date'] == date and
                        appointment['time'] == time and
                        appointment['counselor'] == counselor):
                        return "Sorry, this slot is already booked. Please choose another slot."
                
                # If the slot is available, proceed with booking
                appointment = {
                    'date': date,
                    'time': time,
                    'name': f"{first_name} {last_name}",
                    'email': email,
                    'counselor': counselor,
                    'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                appointment_list.append(appointment)
        
        # Generate a random meeting link
        meeting_link = generate_meeting_link(creds)

        # Send email to student
        student_msg = Message(subject='Appointment Confirmation',
                              recipients=[email],
                              body=f'Hi {first_name},\n\nYour appointment with {counselor} is confirmed for {date} at {time}.\nMeeting Link: {meeting_link}')
        mail.send(student_msg)
        # Send email to counselor
        counselor_email = 'pkumbarkar100@gmail.com'  # Change to counselor's email address
        counselor_msg = Message(subject='New Appointment',
                                recipients=[counselor_email],
                                 body=f'Hi {counselor},\n\nYou have a new appointment with the following student:\n\nName: {first_name} {last_name}\nEmail: {email}\nPhone Number: {phone_number}\nCollege Name: {college_name}\nCollege Registration Number: {college_reg_no}\nAppointment Date: {date}\nAppointment Time: {time}\nMeeting Link: {meeting_link}')
        mail.send(counselor_msg)
        
        return redirect(url_for('appointments'))

# Route for displaying appointments
@app.route('/appointments')
def appointments():
    return render_template('appointments.html', appointments=appointment_list)


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cur.fetchone()
        conn.close()
        if user:
            token = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            expiry_time = datetime.datetime.now() + datetime.timedelta(hours=1)
            conn = get_db_connection()
            cur = conn.cursor()
            cur.execute('INSERT INTO password_resets (email, token, expiry_time) VALUES (?, ?, ?)', (email, token, expiry_time))
            conn.commit()
            conn.close()
            reset_link = url_for('reset_password', token=token, _external=True)
            send_reset_email(email, reset_link)
            flash('An email has been sent with instructions to reset your password.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email address not found. Please try again.', 'error')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM password_resets WHERE token = ?', (token,))
    reset_data = cur.fetchone()
    conn.close()
    if reset_data:
        expiry_time_str = reset_data['expiry_time'].split('.')[0]
        expiry_time = datetime.datetime.strptime(expiry_time_str, '%Y-%m-%d %H:%M:%S')
        if datetime.datetime.now() < expiry_time:
            if request.method == 'POST':
                new_password = request.form['new_password']
                conn = get_db_connection()
                cur = conn.cursor()
                cur.execute('UPDATE users SET password = ? WHERE email = ?', (new_password, reset_data['email']))
                cur.execute('DELETE FROM password_resets WHERE token = ?', (token,))
                conn.commit()
                conn.close()
                flash('Your password has been reset successfully.', 'success')
                return redirect(url_for('login'))
            return render_template('reset_password.html', token=token)
        else:
            flash('The password reset link has expired. Please request a new one.', 'error')
    else:
        flash('Invalid or expired reset token.', 'error')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))




