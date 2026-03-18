"""Database configuration for User Authentication App."""

import os

# SQLite Configuration - File-based database (no password needed)
DB_PATH = os.path.join(os.path.dirname(__file__), 'user_auth.db')

# Flask secret key for session management
SECRET_KEY = 'your-secret-key-change-in-production'
