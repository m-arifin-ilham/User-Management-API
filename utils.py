from flask import request, jsonify, g, current_app  # Import current_app
import jwt

# --- JWT Authentication Decorators ---


def jwt_required(f):
    """Decorator to protect routes that require a valid Access Token."""

    def wrapper(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            auth_header = request.headers["Authorization"]
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"message": "Access Token is missing!"}), 401

        try:
            data = jwt.decode(
                token,
                current_app.config["JWT_SECRET_KEY"],
                algorithms=[current_app.config["JWT_ALGORITHM"]],
            )

            if data.get("type") != "access":
                return (
                    jsonify(
                        {"message": "Invalid token type. An Access Token is required."}
                    ),
                    401,
                )

            g.user = data  # Store decoded user info in Flask's global 'g' object
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Access Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Access Token is invalid!"}), 401
        except Exception as e:
            return jsonify({"message": f"Token error: {str(e)}"}), 401

        return f(*args, **kwargs)

    wrapper.__name__ = (
        f.__name__
    )  # Important for Flask to recognize decorated functions
    return wrapper


def admin_required(f):
    """Decorator to protect routes that require an admin role."""

    @jwt_required  # Ensure JWT is valid first
    def wrapper(*args, **kwargs):
        if not hasattr(g, "user") or g.user.get("role") != "admin":
            return jsonify({"message": "Admin privileges required!"}), 403
        return f(*args, **kwargs)

    wrapper.__name__ = f.__name__
    return wrapper
