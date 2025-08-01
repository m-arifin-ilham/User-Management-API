from abc import ABC, abstractmethod  # For Abstract Base Classes
import sqlite3
from datetime import datetime, timezone

# --- Abstract Base Classes (Interfaces) ---
# These define the 'contract' for what a UserRepository and AuthRepository should do.
# They depend on abstractions (method signatures), not concrete database details.


class UserRepository(ABC):
    def __init__(self, db_connection_func):
        self.get_db_connection = db_connection_func

    @abstractmethod
    def add_user(self, username, email, password_hash, first_name, last_name, role):
        pass

    @abstractmethod
    def find_user_by_id(self, user_id):
        pass

    @abstractmethod
    def find_user_by_username_or_email(self, identifier):
        pass

    @abstractmethod
    def find_password_hash_by_id(self, user_id):
        pass

    @abstractmethod
    def update_user_profile(self, user_id, first_name, last_name, role, is_active):
        pass

    @abstractmethod
    def update_user_password_hash(self, user_id, new_password_hash):
        pass

    @abstractmethod
    def deactivate_user(self, user_id):
        pass

    @abstractmethod
    def get_all_users_paginated(
        self, search_params, limit, offset, include_inactive=False
    ):
        pass

    @abstractmethod
    def get_users_count(self, search_params, include_inactive=False):
        pass


class AuthRepository(ABC):
    def __init__(self, db_connection_func):
        self.get_db_connection = db_connection_func

    @abstractmethod
    def add_refresh_token(self, user_id, token_hash, expires_at):
        pass

    @abstractmethod
    def get_all_active_refresh_tokens(self):
        pass

    @abstractmethod
    def get_all_reset_tokens(self):
        pass

    @abstractmethod
    def revoke_refresh_token_by_id(self, token_id, revoked_at):
        pass

    @abstractmethod
    def delete_password_reset_tokens_for_user(self, user_id):
        pass

    @abstractmethod
    def add_password_reset_token(self, user_id, token_hash, expires_at):
        pass

    @abstractmethod
    def delete_password_reset_token(self, token_hash):
        pass

    @abstractmethod
    def delete_expired_refresh_tokens(self):
        pass

    @abstractmethod
    def delete_expired_reset_tokens(self):
        pass


# --- Concrete Implementations ---
# These classes contain the specific database (SQLite) queries.


class SQLiteUserRepository(UserRepository):
    def add_user(self, username, email, password_hash, first_name, last_name, role):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, email, password_hash, first_name, last_name, role) VALUES (?, ?, ?, ?, ?, ?)",
                (username, email, password_hash, first_name, last_name, role),
            )
            conn.commit()
            return cursor.lastrowid  # Return the ID of the newly created user
        except sqlite3.IntegrityError:
            raise ValueError(
                "Username or email already exists"
            )  # Raise a more specific error
        finally:
            conn.close()

    def find_user_by_id(self, user_id):
        conn = self.get_db_connection()
        user = conn.execute(
            "SELECT id, username, email, first_name, last_name, role, is_active, created_at, updated_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        conn.close()
        return dict(user) if user else None

    def find_user_by_username_or_email(self, identifier):
        conn = self.get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE (username = ? OR email = ?) AND is_active = 1",
            (identifier, identifier),
        ).fetchone()
        conn.close()
        return dict(user) if user else None

    def find_password_hash_by_id(self, user_id):
        conn = self.get_db_connection()
        user = conn.execute(
            "SELECT id, password_hash FROM users WHERE id = ?", (user_id,)
        ).fetchone()
        conn.close()
        return dict(user) if user else None

    def update_user_profile(self, user_id, first_name, last_name, role, is_active):
        conn = self.get_db_connection()
        try:
            conn.execute(
                "UPDATE users SET first_name = ?, last_name = ?, role = ?, is_active = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (first_name, last_name, role, is_active, user_id),
            )
            conn.commit()
            return self.find_user_by_id(user_id)  # Return the updated user data
        except sqlite3.IntegrityError:
            raise ValueError(
                "Username or email already exists"
            )  # Should not happen with current update logic, but good to have
        finally:
            conn.close()

    def update_user_password_hash(self, user_id, new_password_hash):
        conn = self.get_db_connection()
        try:
            conn.execute(
                "UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (new_password_hash, user_id),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def deactivate_user(self, user_id):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET is_active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (user_id,),
            )
            conn.commit()
            return cursor.rowcount > 0  # True if a row was affected
        finally:
            conn.close()

    def get_all_users_paginated(
        self, search_params, limit, offset, include_inactive=False
    ):
        conn = self.get_db_connection()

        where_clauses = []
        params = []

        # Search parameters
        search_username = search_params.get("username")
        search_email = search_params.get("email")
        search_role = search_params.get("role")
        search_is_active = search_params.get("is_active")

        if search_username:
            where_clauses.append("username LIKE ?")
            params.append(f"%{search_username}%")
        if search_email:
            where_clauses.append("email LIKE ?")
            params.append(f"%{search_email}%")
        if search_role:
            where_clauses.append("role = ?")
            params.append(search_role)
        if search_is_active is not None:
            try:
                active_int = int(search_is_active)
                if active_int in [0, 1]:
                    where_clauses.append("is_active = ?")
                    params.append(active_int)
                else:
                    # This should be caught by service layer validation, but as fallback
                    raise ValueError("is_active must be 0 or 1.")
            except ValueError:
                raise ValueError("Invalid value for is_active. Must be 0 or 1.")

        if not include_inactive:  # Only show active users by default
            where_clauses.append("is_active = 1")

        where_sql = ""
        if where_clauses:
            where_sql = " WHERE " + " AND ".join(where_clauses)

        sql_query = f"SELECT id, username, email, first_name, last_name, role, is_active, created_at, updated_at FROM users {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        users = conn.execute(sql_query, params).fetchall()
        conn.close()
        return [dict(user) for user in users]

    def get_users_count(self, search_params, include_inactive=False):
        conn = self.get_db_connection()

        where_clauses = []
        params = []

        # Search parameters
        search_username = search_params.get("username")
        search_email = search_params.get("email")
        search_role = search_params.get("role")
        search_is_active = search_params.get("is_active")

        if search_username:
            where_clauses.append("username LIKE ?")
            params.append(f"%{search_username}%")
        if search_email:
            where_clauses.append("email LIKE ?")
            params.append(f"%{search_email}%")
        if search_role:
            where_clauses.append("role = ?")
            params.append(search_role)
        if search_is_active is not None:
            try:
                active_int = int(search_is_active)
                if active_int in [0, 1]:
                    where_clauses.append("is_active = ?")
                    params.append(active_int)
                else:
                    raise ValueError("is_active must be 0 or 1.")
            except ValueError:
                raise ValueError("Invalid value for is_active. Must be 0 or 1.")

        if not include_inactive:
            where_clauses.append("is_active = 1")

        where_sql = ""
        if where_clauses:
            where_sql = " WHERE " + " AND ".join(where_clauses)

        count_sql = f"SELECT COUNT(*) FROM users {where_sql}"
        total_users = conn.execute(count_sql, params).fetchone()[0]
        conn.close()
        return total_users


class SQLiteAuthRepository(AuthRepository):
    def add_refresh_token(self, user_id, token_hash, expires_at):
        conn = self.get_db_connection()
        try:
            conn.execute(
                "INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                (user_id, token_hash, expires_at.isoformat()),
            )
            conn.commit()
            return True
        finally:
            conn.close()

    def get_all_active_refresh_tokens(self):
        conn = self.get_db_connection()
        # Retrieve all active refresh token hashes and their user_id, expires_at
        try:
            tokens = conn.execute(
                "SELECT id, user_id, token_hash, expires_at, revoked_at FROM refresh_tokens WHERE revoked_at IS NULL"
            ).fetchall()
            return [dict(token) for token in tokens]
        finally:
            conn.close()

    def get_all_reset_tokens(self):
        conn = self.get_db_connection()
        try:
            # Get all active reset tokens
            tokens = conn.execute(
                "SELECT user_id, expires_at, token_hash FROM password_reset_tokens"
            ).fetchall()
            return [dict(token) for token in tokens]
        finally:
            conn.close()

    def revoke_refresh_token_by_id(self, token_id, revoked_at):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?",
                (revoked_at.isoformat(), token_id),
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()

    def revoke_user_refresh_tokens(self, user_id, revoked_at, exclude_token_id=None):
        # This method can be used to revoke all tokens for a user, useful for security actions
        conn = self.get_db_connection()
        try:
            query = "UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL"
            params = [revoked_at.isoformat(), user_id]
            if exclude_token_id:
                query += " AND id != ?"
                params.append(exclude_token_id)
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def delete_expired_refresh_tokens(self):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            # Delete tokens that are expired AND not yet revoked.
            # Or simply delete all expired, whether revoked or not, to clean up.
            cursor.execute(
                "DELETE FROM refresh_tokens WHERE expires_at < ?",
                (datetime.now(timezone.utc).isoformat(),),
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def delete_expired_reset_tokens(self):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            # Delete reset tokens that are expired
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE expires_at < ?",
                (datetime.now(timezone.utc).isoformat(),),
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def delete_password_reset_tokens_for_user(self, user_id):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE user_id = ?", (user_id,)
            )
            conn.commit()
            return cursor.rowcount
        finally:
            conn.close()

    def add_password_reset_token(self, user_id, token_hash, expires_at):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)",
                (user_id, token_hash, expires_at.isoformat()),
            )
            conn.commit()
            return cursor.lastrowid
        finally:
            conn.close()

    def delete_password_reset_token(self, token_hash):
        conn = self.get_db_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM password_reset_tokens WHERE token_hash = ?", (token_hash,)
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
