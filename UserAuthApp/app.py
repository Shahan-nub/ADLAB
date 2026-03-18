"""
User Authentication & Document Sharing Application
Flask + MySQL integration with signup, login, profile management, and grades display.
"""

import os
import sqlite3
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)

# Load config from config.py if available
try:
    from config import DB_PATH, SECRET_KEY
    app.config['SECRET_KEY'] = SECRET_KEY
    app.config['DB_PATH'] = DB_PATH
except ImportError:
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    app.config['DB_PATH'] = os.environ.get('DB_PATH', os.path.join(os.path.dirname(__file__), 'user_auth.db'))

# Upload folder for document sharing
app.config['UPLOAD_FOLDER'] = os.path.join(os.path.dirname(__file__), 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt', 'xlsx', 'xls'}

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


# ============================================
# SQLite Database Helper Functions
# ============================================

def get_db():
    """Get SQLite database connection."""
    conn = sqlite3.connect(app.config['DB_PATH'])
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initialize database tables if they don't exist."""
    conn = get_db()
    cursor = conn.cursor()
    
    # Users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(100) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            full_name VARCHAR(100),
            phone VARCHAR(20),
            address TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Grades table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS grades (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            subject VARCHAR(100) NOT NULL,
            marks REAL NOT NULL,
            max_marks REAL DEFAULT 100,
            grade VARCHAR(10),
            semester VARCHAR(20),
            academic_year VARCHAR(20),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    # Shared documents table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS shared_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title VARCHAR(200) NOT NULL,
            filename VARCHAR(255) NOT NULL,
            file_path VARCHAR(500) NOT NULL,
            shared_with TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    
    conn.commit()
    conn.close()


# Initialize database on startup
init_db()


def login_required(f):
    """Decorator to require login for protected routes."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def allowed_file(filename):
    """Check if file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ============================================
# Authentication Routes
# ============================================

@app.route('/')
def index():
    """Landing page - redirect to login or dashboard."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page for existing users."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if not username or not password:
            flash('Please enter both username and password.', 'danger')
            return render_template('login.html')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT id, username, password, full_name FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['full_name'] = user['full_name'] or user['username']
            flash(f'Welcome back, {session["full_name"]}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Registration form for new users."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        full_name = request.form.get('full_name', '').strip()

        errors = []
        if not username:
            errors.append('Username is required.')
        if not email:
            errors.append('Email is required.')
        if not password:
            errors.append('Password is required.')
        elif len(password) < 6:
            errors.append('Password must be at least 6 characters.')
        if password != confirm_password:
            errors.append('Passwords do not match.')

        if errors:
            for e in errors:
                flash(e, 'danger')
            return render_template('signup.html')

        hashed = generate_password_hash(password, method='scrypt')

        conn = get_db()
        cursor = conn.cursor()
        try:
            cursor.execute(
                "INSERT INTO users (username, email, password, full_name) VALUES (?, ?, ?, ?)",
                (username, email, hashed, full_name or username)
            )
            conn.commit()
            flash('Account created successfully! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError as e:
            if 'username' in str(e).lower():
                flash('Username already exists.', 'danger')
            elif 'email' in str(e).lower():
                flash('Email already registered.', 'danger')
            else:
                flash(f'Registration failed: {str(e)}', 'danger')
            return render_template('signup.html')
        finally:
            conn.close()

    return render_template('signup.html')


@app.route('/logout')
def logout():
    """Logout user."""
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


# ============================================
# Dashboard & Protected Routes
# ============================================

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard after login."""
    return render_template('dashboard.html')


# ============================================
# Profile Management
# ============================================

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """View and update personal details."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT username, email, full_name, phone, address FROM users WHERE id = ?",
        (session['user_id'],)
    )
    user = cursor.fetchone()

    if not user:
        conn.close()
        flash('User not found.', 'danger')
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()

        cursor.execute(
            "UPDATE users SET full_name = ?, phone = ?, address = ? WHERE id = ?",
            (full_name, phone, address, session['user_id'])
        )
        conn.commit()
        conn.close()

        session['full_name'] = full_name or session['username']
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    conn.close()
    return render_template('profile.html', user={
        'username': user['username'],
        'email': user['email'],
        'full_name': user['full_name'] or '',
        'phone': user['phone'] or '',
        'address': user['address'] or '',
    })


@app.route('/reset-password', methods=['GET', 'POST'])
@login_required
def reset_password():
    """Reset password for logged-in user."""
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT password FROM users WHERE id = ?", (session['user_id'],))
        row = cursor.fetchone()

        if not row or not check_password_hash(row['password'], current_password):
            conn.close()
            flash('Current password is incorrect.', 'danger')
            return render_template('reset_password.html')

        if len(new_password) < 6:
            conn.close()
            flash('New password must be at least 6 characters.', 'danger')
            return render_template('reset_password.html')

        if new_password != confirm_password:
            conn.close()
            flash('New passwords do not match.', 'danger')
            return render_template('reset_password.html')

        hashed = generate_password_hash(new_password, method='scrypt')
        cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hashed, session['user_id']))
        conn.commit()
        conn.close()

        flash('Password updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('reset_password.html')


# ============================================
# Grades (Read-Only)
# ============================================

@app.route('/grades')
@login_required
def grades():
    """Display user grades (read-only)."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        """SELECT subject, marks, max_marks, grade, semester, academic_year 
           FROM grades WHERE user_id = ? ORDER BY semester, subject""",
        (session['user_id'],)
    )
    grades_list = cursor.fetchall()
    conn.close()

    grades_data = [
        {
            'subject': row['subject'],
            'marks': float(row['marks']),
            'max_marks': float(row['max_marks']),
            'grade': row['grade'] or '-',
            'semester': row['semester'] or '-',
            'academic_year': row['academic_year'] or '-',
        }
        for row in grades_list
    ]

    return render_template('grades.html', grades=grades_data)


# ============================================
# Document Sharing
# ============================================

@app.route('/documents', methods=['GET', 'POST'])
@login_required
def documents():
    """Upload and view shared documents."""
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected.', 'danger')
            return redirect(url_for('documents'))

        file = request.files['file']
        title = request.form.get('title', '').strip() or file.filename

        if file.filename == '':
            flash('No file selected.', 'danger')
            return redirect(url_for('documents'))

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            conn = get_db()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO shared_documents (user_id, title, filename, file_path) VALUES (?, ?, ?, ?)",
                (session['user_id'], title, filename, filepath)
            )
            conn.commit()
            conn.close()

            flash(f'Document "{title}" uploaded successfully!', 'success')
        else:
            flash('Invalid file type. Allowed: pdf, doc, docx, txt, xlsx, xls', 'danger')

        return redirect(url_for('documents'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, title, filename, created_at FROM shared_documents WHERE user_id = ? ORDER BY created_at DESC",
        (session['user_id'],)
    )
    docs = cursor.fetchall()
    conn.close()

    documents_list = [
        {'id': d['id'], 'title': d['title'], 'filename': d['filename'], 'created_at': str(d['created_at'])}
        for d in docs
    ]

    return render_template('documents.html', documents=documents_list)


# ============================================
# Admin: Add sample grades (for testing)
# ============================================

@app.route('/admin/add-sample-grades')
@login_required
def add_sample_grades():
    """Add sample grades for testing - only if user has none."""
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as count FROM grades WHERE user_id = ?", (session['user_id'],))
    count = cursor.fetchone()['count']
    if count > 0:
        conn.close()
        flash('You already have grades. Sample grades not added.', 'info')
        return redirect(url_for('grades'))

    sample = [
        (session['user_id'], 'Mathematics', 85, 100, 'A', '1', '2024-25'),
        (session['user_id'], 'Physics', 78, 100, 'B+', '1', '2024-25'),
        (session['user_id'], 'Computer Science', 92, 100, 'A+', '1', '2024-25'),
        (session['user_id'], 'English', 88, 100, 'A', '1', '2024-25'),
    ]
    cursor.executemany(
        "INSERT INTO grades (user_id, subject, marks, max_marks, grade, semester, academic_year) VALUES (?, ?, ?, ?, ?, ?, ?)",
        sample
    )
    conn.commit()
    conn.close()
    flash('Sample grades added. View them in the Grades section.', 'success')
    return redirect(url_for('grades'))


if __name__ == '__main__':
    print("\n" + "=" * 50)
    print("User Auth & Document Sharing - http://localhost:5000")
    print("=" * 50 + "\n")
    app.run(debug=True, port=5000)
