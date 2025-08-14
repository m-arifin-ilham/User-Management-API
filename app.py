from flask import Flask, request, jsonify, g
from flask_bcrypt import Bcrypt
import os
from dotenv import load_dotenv
from utils import jwt_required, admin_required  # Import decorators
from flask_cors import CORS

# Import database connection function
from database import get_db_connection, init_db

# Import the concrete repository implementations
from repositories import SQLiteUserRepository, SQLiteAuthRepository

# Import the service classes
from services import UserService, AuthService

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
CORS(app)  # Initialize CORS for the Flask app. This will allow all origins by default.
bcrypt = Bcrypt(app)  # Initialize Bcrypt with the Flask app

# Get secret keys from environment variables
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")
app.config["JWT_ALGORITHM"] = os.getenv(
    "JWT_ALGORITHM", "HS256"
)  # Default to HS256 if not set

# --- JWT Expiration Times ---
app.config["ACCESS_TOKEN_EXPIRE_MINUTES"] = int(
    os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15)
)  # Access token expires quickly, default 15 minutes
app.config["REFRESH_TOKEN_EXPIRE_DAYS"] = int(
    os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7)
)  # Refresh token expires in 7 days

# Ensure secret keys are set
if not app.config["SECRET_KEY"] or not app.config["JWT_SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY and JWT_SECRET_KEY must be set in the .env file")

# Initialize the database when the app starts
init_db()

# --- Initialize Repositories and Services (Dependency Injection here) ---
user_repository = SQLiteUserRepository(get_db_connection)
auth_repository = SQLiteAuthRepository(get_db_connection)
user_service = UserService(user_repository, auth_repository, bcrypt)
auth_service = AuthService(
    user_repository,
    auth_repository,
    bcrypt,
    app.config["JWT_SECRET_KEY"],
    app.config["JWT_ALGORITHM"],
    app.config["ACCESS_TOKEN_EXPIRE_MINUTES"],
    app.config["REFRESH_TOKEN_EXPIRE_DAYS"],
)

# --- API Endpoints ---


# 1. User Registration
@app.route("/register", methods=["POST"])
def register_user_endpoint():
    data = request.get_json()
    try:
        response_data = user_service.register_user(
            data.get("username"),
            data.get("email"),
            data.get("password"),
            data.get("first_name"),
            data.get("last_name"),
            data.get("role", "user"),
        )
        return jsonify(response_data), 201
    except ValueError as e:  # Catch specific business logic errors for validation
        if "already exists" in str(e):
            return jsonify({"message": str(e)}), 409  # Conflict (for duplicates)
        else:
            return (
                jsonify({"message": str(e)}),
                400,
            )  # Bad Request for validation errors
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred during registration",
                    "error": str(e),
                }
            ),
            500,
        )


# 2. User Login
@app.route("/login", methods=["POST"])
def login_user_endpoint():
    data = request.get_json()
    try:
        response_data = auth_service.login_user(
            data.get("username_or_email"), data.get("password")
        )
        return jsonify(response_data), 200
    except ValueError as e:
        if "Invalid credentials" in str(e):
            return (
                jsonify({"message": str(e)}),
                401,
            )  # Unauthorized for invalid credentials
        else:
            return (
                jsonify({"message": str(e)}),
                400,
            )  # Bad Request for other validation errors
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred during login",
                    "error": str(e),
                }
            ),
            500,
        )


# 3. Refresh Access Token
@app.route("/refresh", methods=["POST"])
def refresh_token_endpoint():
    data = request.get_json()
    try:
        response_data = auth_service.refresh_access_token(data.get("refresh_token"))
        return jsonify(response_data), 200
    except ValueError as e:
        if "Invalid or expired Refresh Token" in str(e):
            return (
                jsonify({"message": str(e)}),
                401,
            )  # Unauthorized for invalid/expired token
        elif "not found" in str(e):
            return jsonify({"message": str(e)}), 404
        else:
            return jsonify({"message": str(e)}), 400  # Bad Request for invalid token
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred during token refresh",
                    "error": str(e),
                }
            ),
            500,
        )


# 4. User Logout
@app.route("/logout", methods=["POST"])
@jwt_required  # Requires an access token to identify the user
def logout_user_endpoint():
    data = request.get_json()
    try:
        # g.user is set by jwt_required decorator
        response_data = auth_service.logout_user(
            g.user["user_id"],  # Pass current user's ID to service
            data.get("refresh_token"),
        )
        return jsonify(response_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400  # Bad Request
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred during logout",
                    "error": str(e),
                }
            ),
            500,
        )


# 5. Get User Profile (Own or by Admin)
@app.route("/users/<int:user_id>", methods=["GET"])
@jwt_required
def get_user_endpoint(user_id):
    # Authorization handled by API layer as it depends on g.user from Flask context
    if g.user["user_id"] != user_id and g.user["role"] != "admin":
        return (
            jsonify(
                {
                    "message": "Forbidden: You can only view your own profile unless you are an admin."
                }
            ),
            403,
        )

    try:
        user_data = user_service.get_user_profile(user_id)
        if user_data is None:
            return jsonify({"message": "User not found"}), 404
        return jsonify(user_data), 200
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred while fetching user profile",
                    "error": str(e),
                }
            ),
            500,
        )


# 6. Update User Profile (Own or by Admin)
@app.route("/users/<int:user_id>", methods=["PUT"])
@jwt_required
def update_user_endpoint(user_id):
    update_data = request.get_json()

    # Authorization handled by API layer
    if g.user["user_id"] != user_id and g.user["role"] != "admin":
        return (
            jsonify(
                {
                    "message": "Forbidden: You can only update your own profile unless you are an admin."
                }
            ),
            403,
        )

    # Fields that a regular user CANNOT update for themselves (or for others if not admin)
    forbidden_for_user_update = [
        "role",
        "is_active",
        "password_hash",
        "username",
        "email",
    ]
    if g.user["role"] != "admin":  # If not admin, restrict fields
        for key in forbidden_for_user_update:
            if key in update_data:
                return (
                    jsonify({"message": f"Forbidden: You cannot update '{key}'"}),
                    403,
                )

    try:
        # Role and is_active can only be updated if user is admin
        if g.user["role"] != "admin":
            update_data.pop(
                "role", None
            )  # Ensure role is not passed to service if not admin
            update_data.pop(
                "is_active", None
            )  # Ensure is_active is not passed to service if not admin

        updated_user = user_service.update_user_profile(user_id, update_data)
        if (
            updated_user is None
        ):  # Service might return None if user not found (though update_user_profile raises ValueError)
            return jsonify({"message": "User not found"}), 404
        return jsonify(updated_user), 200
    except ValueError as e:
        if "not found" in str(e):
            return jsonify({"message": str(e)}), 404
        else:
            return jsonify({"message": str(e)}), 400
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred during profile update",
                    "error": str(e),
                }
            ),
            500,
        )


# 7. Change User Password (Logged-in user)
@app.route("/users/<int:user_id>/password", methods=["PUT"])
@jwt_required
def change_password_endpoint(user_id):
    data = request.get_json()

    # Authorization handled by API layer
    if g.user["user_id"] != user_id:
        return (
            jsonify({"message": "Forbidden: You can only change your own password."}),
            403,
        )

    try:
        response_data = user_service.change_user_password(
            user_id, data.get("old_password"), data.get("new_password")
        )
        return jsonify(response_data), 200
    except ValueError as e:
        if "not found" in str(e):
            return jsonify({"message": str(e)}), 404
        elif "new password" in str(e) or "New password must" in str(e):
            return jsonify({"message": str(e)}), 400
        else:
            return (
                jsonify({"message": str(e)}),
                401,
            )  # Unauthorized for incorrect password
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred during password change",
                    "error": str(e),
                }
            ),
            500,
        )


# 8. Soft Delete User (Admin Only)
@app.route("/users/<int:user_id>", methods=["DELETE"])
@admin_required  # Protected by Access Token (via admin_required)
def soft_delete_user_endpoint(user_id):
    # Authorization handled by admin_required decorator
    # Prevent admin from deactivating themselves - this logic moves here too, or remains in service
    if g.user["user_id"] == user_id:
        return (
            jsonify(
                {
                    "message": "Forbidden: Admins cannot deactivate their own account via this endpoint."
                }
            ),
            403,
        )

    try:
        response_data = user_service.deactivate_user(user_id)
        return jsonify(response_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 404  # Not found
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred during user deactivation",
                    "error": str(e),
                }
            ),
            500,
        )


# 9. Get All Users (Admin Only, with Search/Pagination)
@app.route("/users", methods=["GET"])
@admin_required  # Protected by Access Token (via admin_required)
def get_all_users_endpoint():
    try:
        page = request.args.get("page", 1, type=int)
        limit = request.args.get("limit", 10, type=int)
        include_inactive = (
            request.args.get("include_inactive", "false").lower() == "true"
        )

        users_data = user_service.get_all_users(
            request.args, page, limit, include_inactive
        )
        return jsonify(users_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred while fetching all users",
                    "error": str(e),
                }
            ),
            500,
        )


# 10. Request Password Reset Token
@app.route("/forgot-password", methods=["POST"])
def forgot_password_endpoint():
    data = request.get_json()
    try:
        response_data = auth_service.request_password_reset(data.get("email"))
        # Always 200 OK for security reasons (don't reveal if email exists)
        return jsonify(response_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred during password reset request",
                    "error": str(e),
                }
            ),
            500,
        )


# 11. Reset Password with Token
@app.route("/reset-password", methods=["POST"])
def reset_password_endpoint():
    data = request.get_json()
    try:
        response_data = auth_service.reset_password_with_token(
            data.get("token"), data.get("new_password")
        )
        return jsonify(response_data), 200
    except ValueError as e:
        return jsonify({"message": str(e)}), 400  # Invalid/expired token
    except Exception as e:
        return (
            jsonify(
                {
                    "message": "An unexpected error occurred during password reset",
                    "error": str(e),
                }
            ),
            500,
        )


if __name__ == "__main__":
    app.run(debug=True)
