import sqlite3
import bcrypt

DATABASE_NAME = "users.db"


# NOTE: This hash_password is only for the initial admin creation within this file.
# General password hashing will be handled by Bcrypt instance in app.py/services.py.
def _hash_password_for_initial_admin(password):
    """Hashes a password using bcrypt, specifically for initial admin creation."""
    # bcrypt.gensalt() generates a salt, bcrypt.hashpw() hashes the password
    # decode('utf-8') converts the bytes result to a string
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = (
        sqlite3.Row
    )  # This allows us to access rows as dictionary-like objects
    return conn


def init_db():
    """Initializes the database schema if it doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # TABLE FOR USERS
    # This table will store user information including username, email, password hash, and role
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            first_name TEXT,
            last_name TEXT,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """
    )
    # TABLE FOR PASSWORD RESET TOKENS
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE, -- Storing the hash now
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """
    )
    # TABLE FOR REFRESH TOKENS
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT NOT NULL UNIQUE,
            expires_at TIMESTAMP NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            revoked_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    """
    )
    conn.commit()
    conn.close()
    print("Database initialized or already exists.")


def insert_initial_admin():
    """Inserts an initial admin user if one doesn't exist."""
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if an admin user already exists
        cursor.execute("SELECT id FROM users WHERE role = 'admin' LIMIT 1")
        if cursor.fetchone() is None:
            admin_password = "admin_password_123"  # <<< REMEMBER TO CHANGE THIS DEFAULT PASSWORD AFTER CREATION
            # Hash a default admin password
            hashed_admin_password = _hash_password_for_initial_admin(admin_password)

            cursor.execute(
                "INSERT INTO users (username, email, password_hash, first_name, last_name, role, is_active) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "admin",
                    "admin@example.com",
                    hashed_admin_password,
                    "Admin",
                    "User",
                    "admin",
                    1,
                ),
            )
            conn.commit()
            print(
                f"Initial admin user created: username='admin', password='{admin_password}'"
            )
        else:
            print("Admin user already exists. Skipping initial admin insertion.")
    except sqlite3.IntegrityError as e:
        print(f"Error inserting initial admin (likely duplicate username/email): {e}")
        conn.rollback()
    finally:
        conn.close()


if __name__ == "__main__":
    # This block runs only when database.py is executed directly
    init_db()
    insert_initial_admin()
