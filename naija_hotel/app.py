from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import requests
import smtplib
from email.mime.text import MimeText
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change in production
app.config['JWT_SECRET_KEY'] = 'jwt-secret-key'  # Change in production
jwt = JWTManager(app)

# Flutterwave Config (Replace with your keys)
FLUTTERWAVE_PUBLIC_KEY = 'FLWPUBK_TEST-your-public-key'
FLUTTERWAVE_SECRET_KEY = 'FLWSECK_TEST-your-secret-key'
FLUTTERWAVE_BASE_URL = 'https://api.flutterwave.com/v3'

# NubAPI for Bank Verification (Replace with your key)
NUBAPI_KEY = 'your-nubapi-key'

# Email Config (Gmail example)
EMAIL_SERVER = 'smtp.gmail.com'
EMAIL_PORT = 587
EMAIL_USER = 'your-email@gmail.com'
EMAIL_PASS = 'your-app-password'

def get_db():
    conn = sqlite3.connect('hotel.db')
    conn.row_factory = sqlite3.Row
    return conn

# Auth Routes
@app.route('/login', methods=['POST'])
def login():
    data = request.json
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
    data = request.json
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
        data = request.json
        conn.execute('INSERT INTO rooms (room_number, room_type, price_per_night, description) VALUES (?, ?, ?, ?)',
                     (data['room_number'], data['room_type'], data['price_per_night'], data.get('description', '')))
        conn.commit()
    elif request.method == 'PUT':
        data = request.json
        conn.execute('UPDATE rooms SET availability = ? WHERE id = ?', (data['availability'], data['id']))
        conn.commit()
    elif request.method == 'DELETE':
        room_id = request.json['id']
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
    data = request.json
    conn = get_db()
    # Check availability
    room = conn.execute('SELECT * FROM rooms WHERE id = ? AND availability = TRUE', (data['room_id'],)).fetchone()
    if not room:
        conn.close()
        return jsonify({'error': 'Room unavailable'}), 400
    days = (datetime.strptime(data['check_out'], '%Y-%m-%d') - datetime.strptime(data['check_in'], '%Y-%m-%d')).days
    total = room['price_per_night'] * days + data.get('addons_total', 0)
    cur = conn.execute('INSERT INTO bookings (customer_id, room_id, check_in, check_out, total_amount) VALUES (?, ?, ?, ?, ?)',
                       (identity['id'], data['room_id'], data['check_in'], data['check_out'], total))
    booking_id = cur.lastrowid
    # Add add-ons
    for addon in data.get('addons', []):
        conn.execute('INSERT INTO booking_add_ons (booking_id, add_on_id, quantity) VALUES (?, ?, ?)',
                     (booking_id, addon['id'], addon.get('quantity', 1)))
    # Update room availability
    conn.execute('UPDATE rooms SET availability = FALSE WHERE id = ?', (data['room_id'],))
    conn.commit()
    conn.close()
    return jsonify({'booking_id': booking_id, 'total': total})

# Add-ons Management (Admin)
@app.route('/addons', methods=['GET', 'POST'])
@role_required('Admin', 'Super Admin')
def manage_addons():
    conn = get_db()
    if request.method == 'POST':
        data = request.json
        conn.execute('INSERT INTO add_ons (name, price, description) VALUES (?, ?, ?)',
                     (data['name'], data['price'], data.get('description', '')))
        conn.commit()
    addons = conn.execute('SELECT * FROM add_ons').fetchall()
    conn.close()
    return jsonify([dict(row) for row in addons])

# Pool/Restaurant/Housekeeping (Similar CRUD, omitted for brevity; extend as needed)

# Payment Routes
@app.route('/pay/<int:booking_id>', methods=['POST'])
@jwt_required()
def process_payment(booking_id):
    identity = get_jwt_identity()
    data = request.json
    method = data['method']
    amount = data['amount']  # in ₦
    conn = get_db()
    booking = conn.execute('SELECT * FROM bookings WHERE id = ? AND customer_id = ?', (booking_id, identity['id'])).fetchone()
    if not booking:
        conn.close()
        return jsonify({'error': 'Booking not found'}), 404
    cur = conn.execute('INSERT INTO payments (booking_id, amount, payment_method, transaction_id) VALUES (?, ?, ?, ?)',
                       (booking_id, amount, method, data.get('transaction_id', '')))
    payment_id = cur.lastrowid
    conn.commit()
    conn.close()

    if method == 'Card' or method == 'USSD':
        # Flutterwave Integration
        if method == 'Card':
            return flutterwave_charge(amount, booking_id, payment_id, 'card')
        else:  # USSD
            return flutterwave_charge(amount, booking_id, payment_id, 'ussd')
    elif method == 'Bank Transfer':
        # Show bank details and return verification endpoint
        bank_details = {'bank_name': 'GTBank', 'account_number': '0123456789', 'account_name': 'Hotel XYZ'}
        return jsonify({'message': 'Transfer to:', 'details': bank_details, 'verify_url': f'/verify_transfer/{payment_id}'})
    return jsonify({'error': 'Invalid method'}), 400

def flutterwave_charge(amount, booking_id, payment_id, channel):
    headers = {'Authorization': f'Bearer {FLUTTERWAVE_SECRET_KEY}'}
    payload = {
        'tx_ref': f'tx-{booking_id}-{payment_id}',
        'amount': amount,
        'currency': 'NGN',
        'redirect_url': 'http://localhost:5000/payment_success',  # Your callback
        'payment_options': channel,
        'meta': {'booking_id': booking_id},
        'customer': {'email': 'customer@hotel.com', 'phone_number': '08012345678'},
        'customizations': {'title': 'Hotel Booking', 'description': 'Room Payment'}
    }
    if channel == 'card':
        payload['card_number'] = request.json.get('card_number')  # Securely handle in prod
        payload['cvv'] = request.json.get('cvv')
        payload['expiry_month'] = request.json.get('expiry_month')
        payload['expiry_year'] = request.json.get('expiry_year')
        payload['pin'] = request.json.get('pin')  # For debit cards
    response = requests.post(f'{FLUTTERWAVE_BASE_URL}/charges?type={channel}', json=payload, headers=headers)
    if response.status_code == 200:
        data = response.json()
        # Update payment status via webhook in prod
        send_notification('Payment successful! Transaction ID: ' + data['data']['tx_ref'])
        return jsonify({'status': 'success', 'link': data['data'].get('link', '')})  # For USSD, it's a code; for card, redirect
    return jsonify({'error': 'Payment failed'}), 400

@app.route('/verify_transfer/<int:payment_id>', methods=['POST'])
@role_required('Admin', 'Super Admin')
def verify_transfer(payment_id):
    data = request.json
    account_number = data['account_number']
    # NubAPI Verification
    verify_url = f'https://api.nubapi.com/v1/name?bank_code=058&account_number={account_number}'
    headers = {'Authorization': f'Bearer {NUBAPI_KEY}'}
    resp = requests.get(verify_url, headers=headers)
    if resp.status_code == 200 and resp.json().get('data', {}).get('account_name') == 'Hotel XYZ':
        conn = get_db()
        conn.execute('UPDATE payments SET status = "Paid", paid_at = ? WHERE id = ?', (datetime.now(), payment_id))
        conn.execute('UPDATE bookings SET status = "Confirmed" WHERE id = (SELECT booking_id FROM payments WHERE id = ?)', (payment_id,))
        conn.commit()
        conn.close()
        send_notification('Bank transfer verified!')
        return jsonify({'message': 'Verified'})
    return jsonify({'error': 'Invalid transfer'}), 400

def send_notification(message):
    # Email example
    msg = MimeText(message)
    msg['Subject'] = 'Hotel Booking Update'
    msg['From'] = EMAIL_USER
    msg['To'] = 'customer@hotel.com'  # From DB
    with smtplib.SMTP(EMAIL_SERVER, EMAIL_PORT) as server:
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)

# Reports (Staff/Admin)
@app.route('/reports/occupancy')
@jwt_required()
@role_required('Staff', 'Admin', 'Super Admin')
def occupancy_report():
    conn = get_db()
    today = datetime.now().date()
    occupied = conn.execute('SELECT COUNT(*) FROM bookings WHERE status = "Confirmed" AND check_in <= ? AND check_out >= ?',
                            (today, today)).fetchone()[0]
    total_rooms = conn.execute('SELECT COUNT(*) FROM rooms').fetchone()[0]
    rate = (occupied / total_rooms * 100) if total_rooms else 0
    revenue = conn.execute('SELECT SUM(total_amount) FROM bookings WHERE status = "Confirmed"').fetchone()[0] or 0
    conn.close()
    return jsonify({'occupancy_rate': rate, 'revenue': revenue, 'currency': '₦'})

# Frontend Routes (Serve templates)
return render_template('index.html'):
@app.route('/')
def homepage():
    return render_template('index.html')

@app.route('/admin')
@jwt_required()
def admin_dashboard():
    identity = get_jwt_identity()
    if identity['role'] not in ['Admin', 'Super Admin']:
        return redirect(url_for('homepage'))
    return render_template('admin.html')

@app.route('/customer/profile')
@jwt_required()
def customer_profile():
    identity = get_jwt_identity()
    if identity['role'] != 'Customer':
        return redirect(url_for('homepage'))
    return render_template('profile.html')

if __name__ == '__main__':
    app.run(debug=True)