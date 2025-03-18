from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from database import init_db, add_user, get_user, get_water_level_data, add_water_level_data, get_all_users, delete_user, update_user_password
from flask_mail import Mail, Message
from flask import send_file
from functools import wraps
from flask import abort
from flask_wtf.csrf import CSRFProtect
from itsdangerous import URLSafeTimedSerializer
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt
import sqlite3
import requests
import io
import csv


app = Flask(__name__)
app.secret_key = 'rxks tkgc dlaz egcr'
csrf = CSRFProtect(app)


# Configure Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'sankar12022004@gmail.com'
app.config['MAIL_PASSWORD'] = 'rxkstkgcdlazegcr'
mail = Mail(app)

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize the serializer
serializer = URLSafeTimedSerializer(app.secret_key)


# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, username, email, role):
        self.id = id
        self.username = username
        self.email = email
        self.role = role

@login_manager.user_loader
def load_user(user_id):
    user_data = get_user(id=user_id)
    if user_data:
        return User(id=user_data['id'], username=user_data['username'], email=user_data['email'], role=user_data['role'])
    return None

# Routes
@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')
        
        user_data = get_user(email=email)
        
        if not user_data:
            flash("User not found", "danger")
            return redirect(url_for('login'))
        
        # Ensure password comparison is correct
        if bcrypt.checkpw(password, user_data['password_hash'].encode('utf-8')):
            user = User(
                id=user_data['id'],
                username=user_data['username'],
                email=user_data['email'],
                role=user_data['role']
            )
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'danger')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        
        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        try:
            result = add_user(username, email, hashed_password, 'user')
            if result == " Email already exists":
                flash("Email already registered. Please use a different email.", "error")
                return render_template('signup.html')
        except sqlite3.IntegrityError:
            flash("An error occurred. Email already in use.", "error")
            return render_template('signup.html')

        flash("Signup successful!", "success")
        return redirect('/login')

    return render_template('signup.html') # Render the signup page for GET requests



@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user_data = get_user(email=email)
        if user_data:
            # Generate a unique token
            token = serializer.dumps(email, salt='password-reset-salt')
            
            # Send the reset link via email
            reset_url = url_for('reset_password', token=token, _external=True)
            msg = Message('Password Reset Request', sender='sankar12022004@gmail.com', recipients=[email])
            msg.body = f'To reset your password, click the following link: {reset_url}'
            mail.send(msg)
            
            flash('A password reset link has been sent to your email.', 'info')
            return redirect(url_for('login'))
        flash('Email not found.', 'error')
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        print(f"Attempting to load token: {token}")  # Debugging line
        email = serializer.loads(token, salt='password-reset-salt', max_age=3600)  # Token valid for 1 hour
        print(f"Token loaded successfully. Email: {email}")  # Debugging line
    except Exception as e:
        print(f"Error loading token: {e}")  # Debugging line
        flash('The reset link is invalid or has expired.', 'error')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        new_password = request.form['password'].encode('utf-8')
        hashed_password = bcrypt.hashpw(new_password, bcrypt.gensalt()).decode('utf-8')
        
        # Update the user's password in the database
        user_data = get_user(email=email)
        if user_data:
            update_user_password(user_data['id'], hashed_password)
            flash('Your password has been reset successfully!', 'success')
            return redirect(url_for('login'))
        else:
            flash('User not found.', 'error')
    return render_template('reset_password.html', token=token)


@app.route('/export')
def export_csv():
    data = get_water_level_data()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Sensor ID", "Water Level (cm)"])  # CSV Headers
    for row in data:
        writer.writerow([row[3], row[1], row[2]])

    output.seek(0)

    return send_file(
        io.BytesIO(output.getvalue().encode()),
        mimetype="text/csv",
        as_attachment=True,
        download_name="water_level_history.csv"
    )


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the current user is authenticated and has the 'admin' role
        if not current_user.is_authenticated or current_user.role != 'admin':
            abort(403)  # Forbidden access
        return f(*args, **kwargs)
    return decorated_function


@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password'].encode('utf-8')

        # Fetch admin user from the database
        user_data = get_user(email=email)
        page = request.args.get('page', 1, type=int)  # Get the page number from the URL
        users = User.query.paginate(page=page, per_page=10)  # Paginate the query
        
        if user_data and user_data['role'] == 'admin' and bcrypt.checkpw(password, user_data['password_hash'].encode('utf-8')):
            user = User(id=user_data['id'], username=user_data['username'], email=user_data['email'], role=user_data['role'])
            login_user(user)
            flash("Admin login successful!", "success")
            csrf_token = generate_csrf()

            return redirect(url_for('admin_dashboard'))
        
        flash("Invalid admin credentials!", "danger")

    return render_template('admin.html')


@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    users = get_all_users()
    water_data = get_water_level_data()  # Fetch water level data
    return render_template('admin_dashboard.html', users=users, water_data=water_data)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)  # Remove admin from session
    flash("You have logged out.", "info")
    return redirect(url_for('home'))

@app.route('/admin/add_user', methods=['POST'])
@login_required
@admin_required
def add_user_route():
    username = request.form['username']
    email = request.form['email']
    password = request.form['password']
    role = request.form['role']

    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    result = add_user(username, email, hashed_password, role)

    if result == "Email already exists":
        flash("Error: This email is already registered.", "danger")
    else:
        flash("User added successfully!", "success")

    return redirect(url_for('admin_dashboard'))


@app.route('/admin/delete_data/<int:data_id>', methods=['POST'])
@login_required
@admin_required
def delete_data_route(data_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('DELETE FROM water_level_data WHERE id = ?', (data_id,))
    conn.commit()
    conn.close()
    flash('Water level data deleted successfully!', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/api/data', methods=['GET'])
def api_data():
    data = get_water_level_data()
    # Transform data into the required format
    formatted_data = [
        {"timestamp": row[3], "water_level": row[2]}  # Adjust indices based on your data structure
        for row in data
    ]
    return jsonify(formatted_data)

@app.route('/api/add_data', methods=['POST'])
def api_add_data():
    data = request.json
    sensor_id = data.get('sensor_id')
    water_level = data.get('water_level')
    if sensor_id is not None and water_level is not None:
        add_water_level_data(sensor_id, water_level)
        return jsonify({"status": "success"}), 200
    return jsonify({"status": "error", "message": "Invalid data"}), 400


@app.route('/forgot-password',endpoint='forgot_password_1')
def forgot_password():
    return "Forgot Password page"

@app.route('/reset-password',endpoint='reset_password_2')
def reset_password():
    return "Reset Password Page"


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/dashboard')
@login_required
def dashboard():
    data = get_water_level_data()
    # Convert data to a format suitable for Chart.js
    timestamps = [row[3] for row in data]
    water_levels = [row[2] for row in data]
    return render_template('dashboard.html', timestamps=timestamps, water_levels=water_levels)

@app.route('/history')
def history():
    data = get_water_level_data()
    return render_template('history.html', data=data)


if __name__ == '__main__':
    init_db()
    app.run(debug=True)