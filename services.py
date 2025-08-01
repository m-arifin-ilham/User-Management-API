from repositories import UserRepository, AuthRepository  # Import our repository ABCs
from datetime import datetime, timezone, timedelta
import re  # Regular expressions for validation
import jwt
import secrets
from flask_bcrypt import Bcrypt  # We'll pass the Bcrypt instance here

# --- Service Layer ---
# These classes contain the "what to do" logic.
# They depend on abstractions (UserRepository, AuthRepository), not concrete database implementations.


class UserService:
    def __init__(
        self,
        user_repo: UserRepository,
        auth_repo: AuthRepository,
        bcrypt_instance: Bcrypt,
    ):
        self.user_repo = user_repo
        self.auth_repo = auth_repo
        self.bcrypt = (
            bcrypt_instance  # Receive bcrypt instance via dependency injection
        )

    def register_user(
        self, username, email, password, first_name, last_name, role="user"
    ):
        if not username or not email or not password:
            raise ValueError("Username, email, and password are required")
        if not (3 <= len(username) <= 20) or not username.isalnum():
            raise ValueError("Username must be 3-20 alphanumeric characters.")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            raise ValueError("Invalid email format.")
        if not (
            len(password) >= 8
            and any(char.isdigit() for char in password)
            and any(char.isalpha() for char in password)
        ):
            raise ValueError(
                "Password must be at least 8 characters long and contain both letters and numbers."
            )
        if role not in ["user", "admin"]:
            raise ValueError("Invalid role specified")

        password_hash = self.bcrypt.generate_password_hash(password).decode("utf-8")
        try:
            user_id = self.user_repo.add_user(
                username, email, password_hash, first_name, last_name, role
            )
            return {"message": "User registered successfully", "user_id": user_id}
        except ValueError as e:  # Catch the specific error raised by repository
            raise ValueError(str(e))  # Re-raise for the API layer to handle

    def get_user_profile(self, user_id):
        user = self.user_repo.find_user_by_id(user_id)
        if user:
            # Remove sensitive fields before returning
            user.pop("password_hash", None)
            return user
        return None

    def update_user_profile(self, target_user_id, update_data):
        user = self.user_repo.find_user_by_id(target_user_id)
        if not user:
            raise ValueError("User not found")

        # Validate role if it's being updated
        if "role" in update_data and update_data["role"] not in ["user", "admin"]:
            raise ValueError("Invalid role specified")

        # Basic type/length checks for first_name/last_name if you want
        if "first_name" in update_data and not isinstance(
            update_data["first_name"], str
        ):
            raise ValueError("First name must be a string.")
        if "last_name" in update_data and not isinstance(update_data["last_name"], str):
            raise ValueError("Last name must be a string.")

        # Extract fields, apply existing values if not provided in update_data
        first_name = update_data.get("first_name", user["first_name"])
        last_name = update_data.get("last_name", user["last_name"])
        role = update_data.get("role", user["role"])
        is_active = update_data.get("is_active", user["is_active"])

        # Perform update
        updated_user = self.user_repo.update_user_profile(
            target_user_id, first_name, last_name, role, is_active
        )
        if updated_user:
            updated_user.pop("password_hash", None)  # Clean sensitive data
        return updated_user

    def change_user_password(self, user_id, old_password, new_password):
        if not old_password or not new_password:
            raise ValueError("Old password and new password are required")

        if not (
            len(new_password) >= 8
            and any(char.isdigit() for char in new_password)
            and any(char.isalpha() for char in new_password)
        ):
            raise ValueError(
                "New password must be at least 8 characters long and contain both letters and numbers."
            )

        user = self.user_repo.find_password_hash_by_id(user_id)

        if not user:
            raise ValueError("User not found")

        if not self.bcrypt.check_password_hash(user["password_hash"], old_password):
            raise ValueError("Incorrect old password")

        hashed_new_password = self.bcrypt.generate_password_hash(new_password).decode(
            "utf-8"
        )
        self.user_repo.update_user_password_hash(user_id, hashed_new_password)
        return {"message": "Password updated successfully"}

    def deactivate_user(self, user_id):
        user_exists = self.user_repo.find_user_by_id(user_id)
        if not user_exists:
            raise ValueError("User not found")

        success = self.user_repo.deactivate_user(user_id)
        if not success:
            raise RuntimeError(
                "Failed to deactivate user"
            )  # Should ideally not happen if user_exists check passes

        # Optionally, you can also revoke all refresh tokens for this user
        self.auth_repo.revoke_user_refresh_tokens(user_id, datetime.now(timezone.utc))
        return {"message": "User deactivated successfully"}

    def get_all_users(self, search_params, page, limit, include_inactive=False):
        if page < 1:
            raise ValueError("Page number must be 1 or greater.")
        if limit < 1:
            raise ValueError("Limit must be 1 or greater.")

        search_is_active = search_params.get("is_active")
        if search_is_active is not None:
            try:
                active_int = int(search_is_active)
                if active_int not in [0, 1]:
                    raise ValueError("Invalid value for 'is_active'. Must be 0 or 1.")
            except ValueError:
                raise ValueError(
                    "Invalid value for 'is_active'. Must be a number (0 or 1)."
                )

        offset = (page - 1) * limit

        users = self.user_repo.get_all_users_paginated(
            search_params, limit, offset, include_inactive
        )
        total_users = self.user_repo.get_users_count(search_params, include_inactive)

        total_pages = (total_users + limit - 1) // limit

        # Remove password_hash from each user before returning
        for user in users:
            user.pop("password_hash", None)

        return {
            "data": users,
            "pagination": {
                "total_items": total_users,
                "total_pages": total_pages,
                "current_page": page,
                "items_per_page": limit,
                "next_page": page + 1 if page < total_pages else None,
                "prev_page": page - 1 if page > 1 else None,
            },
        }


class AuthService:
    def __init__(
        self,
        user_repo: UserRepository,
        auth_repo: AuthRepository,
        bcrypt_instance: Bcrypt,
        jwt_secret_key: str,
        jwt_algorithm: str,
        access_token_expire_minutes: int,
        refresh_token_expire_days: int,
    ):
        self.user_repo = user_repo
        self.auth_repo = auth_repo
        self.bcrypt = bcrypt_instance
        self.jwt_secret_key = jwt_secret_key
        self.jwt_algorithm = jwt_algorithm
        self.access_token_expire_minutes = access_token_expire_minutes
        self.refresh_token_expire_days = refresh_token_expire_days

    def login_user(self, username_or_email, password):
        if not username_or_email or not password:
            raise ValueError("Username/Email and password are required")

        user = self.user_repo.find_user_by_username_or_email(username_or_email)
        if not user or not self.bcrypt.check_password_hash(
            user["password_hash"], password
        ):
            raise ValueError("Invalid credentials or inactive account")

        access_token = self._generate_access_token(
            user["id"], user["username"], user["role"]
        )
        refresh_token = self._generate_refresh_token(user["id"])

        return {
            "message": "Login successful",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "user_id": user["id"],
            "role": user["role"],
        }

    def _generate_access_token(self, user_id, username, role):
        payload = {
            "user_id": user_id,
            "username": username,
            "role": role,
            "type": "access",
            "exp": datetime.now(timezone.utc)
            + timedelta(minutes=self.access_token_expire_minutes),
        }
        return jwt.encode(payload, self.jwt_secret_key, algorithm=self.jwt_algorithm)

    def _generate_refresh_token(self, user_id):
        refresh_token = secrets.token_urlsafe(64)
        refresh_token_hash = self.bcrypt.generate_password_hash(refresh_token).decode(
            "utf-8"
        )
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=self.refresh_token_expire_days
        )

        self.auth_repo.add_refresh_token(user_id, refresh_token_hash, expires_at)
        return refresh_token

    def refresh_access_token(self, refresh_token_plain: str):
        if not refresh_token_plain:
            raise ValueError("Refresh Token is missing!")

        # 1. Find the refresh token in the database by iterating and checking hash
        # Uncomment the line below if you want to clean up expired tokens to optimize checks
        # self.auth_repo.delete_expired_refresh_tokens()
        all_active_refresh_tokens = self.auth_repo.get_all_active_refresh_tokens()
        valid_token_record = None
        for record in all_active_refresh_tokens:
            try:
                if self.bcrypt.check_password_hash(
                    record["token_hash"], refresh_token_plain
                ):
                    valid_token_record = record
                    break
            except ValueError:
                continue  # Skip malformed hashes

        if not valid_token_record:
            raise ValueError("Invalid or expired Refresh Token.")

        # 2. Validate the found token
        if datetime.now(timezone.utc) > datetime.fromisoformat(
            valid_token_record["expires_at"]
        ):
            self.auth_repo.revoke_refresh_token_by_id(
                valid_token_record["id"], datetime.now(timezone.utc)
            )
            raise ValueError("Invalid or expired Refresh Token.")

        if valid_token_record["revoked_at"] is not None:
            raise ValueError("Invalid or expired Refresh Token.")

        # 3. Get the user associated with this valid refresh token
        user = self.user_repo.find_user_by_id(valid_token_record["user_id"])
        if user is None or user["is_active"] == 0:
            self.auth_repo.revoke_refresh_token_by_id(
                valid_token_record["id"], datetime.now(timezone.utc)
            )
            raise ValueError("Associated user not found or inactive.")

        # --- All Validations Passed! ---

        # 4. Revoke the old refresh token
        self.auth_repo.revoke_refresh_token_by_id(
            valid_token_record["id"], datetime.now(timezone.utc)
        )

        # 5. Generate new tokens
        new_access_token = self._generate_access_token(
            user["id"], user["username"], user["role"]
        )
        new_refresh_token = self._generate_refresh_token(user["id"])

        return {
            "message": "Tokens refreshed successfully",
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
        }

    def logout_user(self, user_id, refresh_token_plain: str):
        if not refresh_token_plain:
            raise ValueError("Refresh token is required to logout.")

        user_refresh_tokens = self.auth_repo.get_all_active_refresh_tokens()

        token_found_and_matched = False
        for record in user_refresh_tokens:
            if record["user_id"] == user_id:  # Filter by current user
                try:
                    if self.bcrypt.check_password_hash(
                        record["token_hash"], refresh_token_plain
                    ):
                        self.auth_repo.revoke_refresh_token_by_id(
                            record["id"], datetime.now(timezone.utc)
                        )
                        token_found_and_matched = True
                        break
                except ValueError:
                    continue

        if not token_found_and_matched:
            raise ValueError(
                "Refresh Token not found for this user or already revoked."
            )

        return {"message": "Logged out successfully (Refresh Token revoked)."}

    def request_password_reset(self, email: str):
        if not email:
            raise ValueError("Email is required")

        user = self.user_repo.find_user_by_username_or_email(email)

        if user:
            user_id = user["id"]
            username = user["username"]
            email = user["email"]

            self.auth_repo.delete_password_reset_tokens_for_user(
                user_id
            )  # Invalidate existing tokens sent for user
            token = secrets.token_urlsafe(32)
            hashed_token = self.bcrypt.generate_password_hash(token).decode(
                "utf-8"
            )  # Hash the token
            expires_at = datetime.now(timezone.utc) + timedelta(hours=1)

            self.auth_repo.add_password_reset_token(user_id, hashed_token, expires_at)

            # --- SIMULATE EMAIL SENDING ---
            print(f"Address email to: {email}")
            print(f"\n--- PASSWORD RESET REQUEST FOR {username} ---")
            print(f"To reset password, use this token: {token}")
            print(f"Token expires at: {expires_at.isoformat()} UTC\n")
            # --- END SIMULATION ---

        # Always return a generic message for security
        return {
            "message": "If an account with that email exists, a password reset instruction has been sent to the associated email."
        }

    def reset_password_with_token(self, token_plain: str, new_password: str):
        if not token_plain or not new_password:
            raise ValueError("Token and new password are required")

        if not (
            len(new_password) >= 8
            and any(char.isdigit() for char in new_password)
            and any(char.isalpha() for char in new_password)
        ):
            raise ValueError(
                "New password must be at least 8 characters long and contain both letters and numbers."
            )

        # Fetch ALL potentially valid reset tokens from the DB (those not expired)
        # and then iterate to find a hash match. This is more secure for the DB.

        self.auth_repo.delete_expired_reset_tokens()  # Clean up expired tokens to optimize checks
        active_reset_tokens = self.auth_repo.get_all_reset_tokens()

        valid_token_record = None
        for record in active_reset_tokens:
            # Check if not expired and hash matches
            if datetime.now(timezone.utc) <= datetime.fromisoformat(
                record["expires_at"]
            ):
                try:
                    if self.bcrypt.check_password_hash(
                        record["token_hash"], token_plain
                    ):
                        valid_token_record = record
                        break
                except ValueError:
                    continue

        if not valid_token_record:
            raise ValueError("Invalid or expired token.")

        user_id_from_token = valid_token_record["user_id"]
        hashed_new_password = self.bcrypt.generate_password_hash(new_password).decode(
            "utf-8"
        )

        self.user_repo.update_user_password_hash(
            user_id_from_token, hashed_new_password
        )  # Update the user's password in the DB
        self.auth_repo.delete_password_reset_token(
            valid_token_record["token_hash"]
        )  # Invalidate used token

        return {"message": "Password has been reset successfully."}
