import sqlite3
from werkzeug.security import generate_password_hash

# Connect to DB (creates if missing)
conn = sqlite3.connect('hotel.db')
cur = conn.cursor()

# Create tables (if not exist) - full schema
cur.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT CHECK(role IN ('Super Admin', 'Admin', 'Staff', 'Customer')) NOT NULL,
    email TEXT UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    full_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    room_number TEXT UNIQUE NOT NULL,
    room_type TEXT NOT NULL,
    price_per_night REAL NOT NULL,
    availability BOOLEAN DEFAULT TRUE,
    description TEXT
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS bookings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    customer_id INTEGER,
    room_id INTEGER,
    check_in DATE NOT NULL,
    check_out DATE NOT NULL,
    total_amount REAL NOT NULL,
    status TEXT DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (customer_id) REFERENCES customers (id),
    FOREIGN KEY (room_id) REFERENCES rooms (id)
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    booking_id INTEGER,
    amount REAL NOT NULL,
    payment_method TEXT CHECK(payment_method IN ('Bank Transfer', 'USSD', 'Card')) NOT NULL,
    transaction_id TEXT UNIQUE,
    status TEXT DEFAULT 'Pending',
    paid_at TIMESTAMP,
    FOREIGN KEY (booking_id) REFERENCES bookings (id)
)
""")

cur.execute("""
CREATE TABLE IF NOT EXISTS add_ons (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    description TEXT
)
""")

# Sample Data
hashed_admin = generate_password_hash('adminpass')  # Secure hash
cur.execute("INSERT OR IGNORE INTO users (id, username, password, role, email) VALUES (1, ?, ?, 'Admin', 'admin@hotel.com')", ( 'admin', hashed_admin ))

cur.execute("INSERT OR IGNORE INTO customers (id, user_id, full_name, phone) VALUES (1, 1, 'Admin User', '08012345678')")

cur.execute("INSERT OR IGNORE INTO rooms (id, room_number, room_type, price_per_night, description) VALUES (1, '101', 'Single', 25000.00, 'Standard single room')")

cur.execute("INSERT OR IGNORE INTO add_ons (id, name, price, description) VALUES (1, 'Pool Access', 5000.00, 'Hourly pool access')")

conn.commit()
conn.close()
print("Database initialized! Admin login: username='admin', password='adminpass'")