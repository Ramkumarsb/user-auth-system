from flask import Flask, request, jsonify
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import sqlite3

# Initialize the Flask app
app = Flask(__name__)

# Set the JWT Secret Key for authentication
app.config['JWT_SECRET_KEY'] = 'your_jwt_secret_key'  # Replace with your actual secret key
jwt = JWTManager(app)


# Initialize the database
def init_db():
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Create tables
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS roles (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role_name TEXT UNIQUE NOT NULL
    )''')

    # Insert default roles and Superadmin user
    cursor.execute("INSERT OR IGNORE INTO roles (role_name) VALUES ('Superadmin'), ('Admin'), ('Superuser'), ('User')")
    cursor.execute(
        "INSERT OR IGNORE INTO users (username, password, role) VALUES ('superadmin', 'supersecurepassword', 'Superadmin')")

    conn.commit()
    conn.close()


init_db()


# JWT Authentication - Login Route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check credentials in the database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
    user = cursor.fetchone()

    if user:
        access_token = create_access_token(identity={'username': user[1], 'role': user[3]})
        return jsonify(access_token=access_token)
    else:
        return jsonify({"msg": "Invalid username or password"}), 401


# Role-based access control decorator
def role_required(allowed_roles):
    def wrapper(fn):
        @jwt_required()
        def decorator(*args, **kwargs):
            user = get_jwt_identity()
            if user['role'] not in allowed_roles:
                return jsonify({"msg": "Access forbidden: insufficient permissions"}), 403
            return fn(*args, **kwargs)

        return decorator

    return wrapper
S

# Protected route - Admin dashboard
@app.route('/admin-dashboard', methods=['GET'])
@role_required(['Superadmin', 'Admin'])
def admin_dashboard():
    return jsonify({"msg": "Welcome to the admin dashboard"})


# Superadmin-only route
@app.route('/superadmin-only', methods=['GET'])
@role_required(['Superadmin'])
def superadmin_dashboard():
    return jsonify({"msg": "Welcome to the Superadmin dashboard"})


if __name__ == '__main__':
    app.run(debug=True)
