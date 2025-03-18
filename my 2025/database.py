import sqlite3
import bcrypt

DATABASE = 'water_monitoring.db'

def get_db_connection():
    """Returns a connection to the database"""
    return sqlite3.connect(DATABASE)

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()

    # Create Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL
        )
    ''')

    # Create Water Level Data Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS water_level_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sensor_id TEXT NOT NULL,
            water_level REAL NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    conn.commit()
    conn.close()

def update_user_password(user_id, new_password_hash):
    """Updates the password of a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_password_hash, user_id))
    conn.commit()
    conn.close()

def add_user(username, email, password_hash, role):
    """Adds a new user to the database"""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Check if the email already exists
    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    existing_user = cursor.fetchone()

    if existing_user:
        conn.close()
        return " Email already exists"

    # Insert new user
    try:
        cursor.execute("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)", 
                       (username, email, password_hash, role))
        conn.commit()
        conn.close()
        return " User added successfully"
    except sqlite3.IntegrityError:
        conn.close()
        return " Email already exists"
    
def get_user(email=None, id=None):
    """Fetches user details by email or ID"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    if email:
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
    elif id:
        cursor.execute('SELECT * FROM users WHERE id = ?', (id,))
    
    user = cursor.fetchone()
    conn.close()

    if user:
        return {'id': user[0], 'username': user[1], 'email': user[2], 'password_hash': user[3], 'role': user[4]}
    return None

def get_all_users():
    """Fetches all users from the database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users')
    users = cursor.fetchall()
    conn.close()
    return users

def delete_user(user_id):
    """Deletes a user from the database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

def add_water_level_data(sensor_id, water_level):
    """Adds a water level reading to the database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO water_level_data (sensor_id, water_level) VALUES (?, ?)',
                   (sensor_id, water_level))
    conn.commit()
    conn.close()

def get_water_level_data():
    """Fetches water level data from the database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM water_level_data ORDER BY timestamp DESC')
    data = cursor.fetchall()
    conn.close()
    return data

# Run the function to create tables
init_db()