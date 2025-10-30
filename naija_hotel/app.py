from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps  # Added for role_required decorator
import sqlite3
import requests
import smtplib
from email.mime.text import MimeText
from datetime import datetime, timedelta
import os  # For env vars

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')  # From env or default
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-secret-key')  # From env or default
jwt = JWTManager(app)

# Flutterwave Config (From env or default)
FLUTTERWAVE_PUBLIC_KEY = os.getenv('FLUTTERWAVE_PUBLIC_KEY', 'FLWPUBK_TEST-your-public-key')
FLUTTERWAVE_SECRET_KEY = os.getenv('FLUTTERWAVE_SECRET_KEY', 'FLWSECK_TEST-your-secret-key')
FLUTTERWAVE_BASE_URL = 'https://api.flutterwave.com/v3'

# NubAPI for Bank Verification (From env or default)
NUBAPI_KEY = os.getenv('NUBAPI_KEY', 'your-nubapi-key')

# Email Config (From env or default)
EMAIL_SERVER = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USER = os.getenv('EMAIL_USER', 'your-email@gmail.com')
EMAIL_PASS = os.getenv('EMAIL_PASS', 'your-app-password')

def get_db():
    conn = sqlite3.connect('hotel.db')
    conn.row_factory = sqlite3.Row
    return conn

# Auth Routes
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    conn = get_db()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (data['username'],)).fetchone()
    conn.close()
    if user and check_password_hash(user['password'], data['password']):
        access_token = create_access_token(identity={'id': user['id'], 'role': user['role']})
        return jsonify({'token': access_token})
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/register', methods=['POST'])
@jwt_required()
def register():
    identity = get_jwt_identity()
    if identity['role'] not in ['Admin', 'Super Admin']:
        return jsonify({'error': 'Insufficient permissions'}), 403
    data = request.get_json()
    hashed_pw = generate_password_hash(data['password'])
    conn = get_db()
    try:
        cur = conn.execute('INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)',
                           (data['username'], hashed_pw, data['role'], data['email']))
        if data['role'] == 'Customer':
            conn.execute('INSERT INTO customers (user_id, full_name, phone) VALUES (?, ?, ?)',
                         (cur.lastrowid, data.get('full_name', ''), data.get('phone', '')))
        conn.commit()
        return jsonify({'message': 'User created'})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Username/Email exists'}), 400
    finally:
        conn.close()

# Role-based decorator example
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        @jwt_required()
        def decorated_function(*args, **kwargs):
            identity = get_jwt_identity()
            if identity['role'] not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Customer Management (Admin only)
@app.route('/customers', methods=['GET', 'POST'])
@role_required('Admin', 'Super Admin')
def manage_customers():
    conn = get_db()
    if request.method == 'POST':
        # Update logic here
        pass
    customers = conn.execute('SELECT * FROM customers JOIN users ON customers.user_id = users.id').fetchall()
    conn.close()
    return jsonify([dict(row) for row in customers])

# Room Management (Admin only)
@app.route('/rooms', methods=['GET', 'POST', 'PUT', 'DELETE'])
@role_required('Admin', 'Super Admin')
def manage_rooms():
    conn = get_db()
    if request.method == 'POST':
        data = request.get_json()
        conn.execute('INSERT INTO rooms (room_number, room_type, price_per_night, description) VALUES (?, ?, ?, ?)',
                     (data['room_number'], data['room_type'], data['price_per_night'], data.get('description', '')))
        conn.commit()
    elif request.method == 'PUT':
        data = request.get_json()
        conn.execute('UPDATE rooms SET availability = ? WHERE id = ?', (data['availability'], data['id']))
        conn.commit()
    elif request.method == 'DELETE':
        data = request.get_json()
        room_id = data['id']
        conn.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
        conn.commit()
    rooms = conn.execute('SELECT * FROM rooms').fetchall()
    conn.close()
    return jsonify([dict(row) for row in rooms])

# Booking System (Customer)
@app.route('/book', methods=['POST'])
@jwt_required()
def create_booking():
    identity = get_jwt_identity()
    if identity['role'] != 'Customer':
        return jsonify({'error': 'Only customers can book'}), 403
    data = request.get_json()
    conn = get_db()
    # Check availability
    room = conn.execute('SELECT * FROM rooms WHERE id = ? AND availability = TRUE', (data['room_id'],)).fetchone()
    if not room:
        conn.close()
        return jsonify({'error': 'Room unavailable'}), 400
    days = (datetime.strptime(data['check_out'], '%Y-%m-%d') - datetime.strptime(data['check_in'], '%Y-%m-%d')).days
    total = room['price_per_night'] * days + data.get('addons_total', 0)
    # Assume customer_id = user_id for simplicity
    customer_id = identity['id']
    cur = conn.execute('INSERT INTO bookings (customer_id, room_id, check_in, check_out, total_amount) VALUES (?, ?, ?, ?, ?)',
                       (customer_id, data['room_id'], data['check_in'], data['check_out'], total))
    booking_id = cur.lastrowid
    # Add add-ons
    for addon in data.get('addons', []):
        conn.execute('INSERT INTO booking_add_ons (booking_id, add_on_id, quantity) VALUES (?, ?, ?)',
                     (booking_id
