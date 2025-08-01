# --- Instructions ---
# 1. Ensure your Flask server is running in another terminal.
# 2. For Phase 5, set ACCESS_TOKEN_EXPIRE_MINUTES to 1 in your .env file and restart the server.
# 3. For Phase 4, keep an eye on your Flask terminal to copy the password reset token.

import requests
import json
import time

# --- Configuration ---
BASE_URL = "http://127.0.0.1:5000"

# Sample user data for registration and testing
TEST_USER_DATA = {
    "username": "testuser",
    "email": "testuser@example.com",
    "password": "test_password_123A",
}
TEST_ADMIN_DATA = {
    "username": "adminuser",
    "email": "adminuser@example.com",
    "password": "admin_password_123A",
    "role": "admin",
}

# Global variables to store tokens and user IDs
admin_access_token = ""
admin_refresh_token = ""
regular_access_token = ""
regular_refresh_token = ""
regular_user_id = 0
admin_user_id = 0


# --- Helper Functions ---
def print_status(message, response):
    """Prints the status code and response for an API call."""
    print(f"\n--- {message} ---")
    print(f"Status Code: {response.status_code}")
    try:
        print(f"Response: {json.dumps(response.json(), indent=2)}")
    except json.JSONDecodeError:
        print(f"Response: {response.text}")


def make_request(method, endpoint, data=None, token_type=None, token=None):
    """A helper function to make API requests with optional authentication."""
    headers = {"Content-Type": "application/json"}
    if token and token_type:
        headers["Authorization"] = f"Bearer {token}"

    url = f"{BASE_URL}{endpoint}"

    if method == "POST":
        return requests.post(url, json=data, headers=headers)
    elif method == "GET":
        return requests.get(url, params=data, headers=headers)
    elif method == "PUT":
        return requests.put(url, json=data, headers=headers)
    elif method == "DELETE":
        return requests.delete(url, headers=headers)


# --- Main Test Execution ---
def run_tests():
    global admin_access_token, admin_refresh_token, regular_access_token, regular_refresh_token, regular_user_id, admin_user_id

    # PHASE 1: User Registration
    print("\n\n##################################")
    print("#  PHASE 1: USER REGISTRATION  #")
    print("##################################")

    # Test 1: Register a regular user
    print("Test 1.1: Registering a new regular user...")
    response = make_request("POST", "/register", TEST_USER_DATA)
    print_status("User Registration", response)
    assert response.status_code == 201
    regular_user_id = response.json()["user_id"]

    # Test 2: Register a user with an existing username (should fail)
    print("Test 1.2: Attempting to register with existing username...")
    response = make_request("POST", "/register", TEST_USER_DATA)
    print_status("Duplicate Username Registration", response)
    assert response.status_code == 409

    # Test 3: Register an admin user
    print("Test 1.3: Registering a new admin user...")
    response = make_request("POST", "/register", TEST_ADMIN_DATA)
    print_status("Admin User Registration", response)
    assert response.status_code == 201
    admin_user_id = response.json()["user_id"]

    # PHASE 2: Login & Token Flow
    print("\n\n#################################")
    print("#  PHASE 2: LOGIN & TOKEN FLOW  #")
    print("#################################")

    # Test 4: Login as the regular user
    print("Test 2.1: Logging in as the regular user...")
    login_data = {
        "username_or_email": TEST_USER_DATA["username"],
        "password": TEST_USER_DATA["password"],
    }
    response = make_request("POST", "/login", login_data)
    print_status("Regular User Login", response)
    assert response.status_code == 200
    regular_access_token = response.json()["access_token"]
    regular_refresh_token = response.json()["refresh_token"]

    # Test 5: Login as the admin user
    print("Test 2.2: Logging in as the admin user...")
    login_data = {
        "username_or_email": TEST_ADMIN_DATA["email"],
        "password": TEST_ADMIN_DATA["password"],
    }
    response = make_request("POST", "/login", login_data)
    print_status("Admin User Login", response)
    assert response.status_code == 200
    admin_access_token = response.json()["access_token"]
    admin_refresh_token = response.json()["refresh_token"]

    # Test 6: Access protected endpoint with valid token
    print("Test 2.3: Accessing own profile with valid access token...")
    response = make_request(
        "GET",
        f"/users/{regular_user_id}",
        token_type="Bearer",
        token=regular_access_token,
    )
    print_status("Get User Profile (Authorized)", response)
    assert response.status_code == 200

    # Test 7: Access protected endpoint with wrong user's token
    print(
        "Test 2.4: Attempting to access admin's profile as regular user (should be forbidden)..."
    )
    response = make_request(
        "GET",
        f"/users/{admin_user_id}",
        token_type="Bearer",
        token=regular_access_token,
    )
    print_status("Get Other User Profile (Forbidden)", response)
    assert response.status_code == 403

    # PHASE 3: Admin Actions
    print("\n\n###############################")
    print("#  PHASE 3: ADMIN ACTIONS  #")
    print("###############################")

    # Test 8: Admin gets all users
    print("Test 3.1: Admin getting all active users...")
    response = make_request(
        "GET", "/users", token_type="Bearer", token=admin_access_token
    )
    print_status("Admin Get All Users", response)
    assert response.status_code == 200
    assert len(response.json()["data"]) >= 2

    # Test 9: Admin updates a regular user
    print("Test 3.2: Admin updating a regular user's profile...")
    update_data = {"first_name": "Updated", "last_name": "User"}
    response = make_request(
        "PUT",
        f"/users/{regular_user_id}",
        update_data,
        token_type="Bearer",
        token=admin_access_token,
    )
    print_status("Admin Update User", response)
    assert response.status_code == 200
    assert response.json()["first_name"] == "Updated"

    # Test 10: Admin deactivates a regular user
    print("Test 3.3: Admin deactivating a regular user...")
    response = make_request(
        "DELETE",
        f"/users/{regular_user_id}",
        token_type="Bearer",
        token=admin_access_token,
    )
    print_status("Admin Deactivate User", response)
    assert response.status_code == 200

    # Test 11: Deactivated user attempts to login (should fail)
    print("Test 3.4: Deactivated user attempts to login (should fail)...")
    login_data = {
        "username_or_email": TEST_USER_DATA["username"],
        "password": TEST_USER_DATA["password"],
    }
    response = make_request("POST", "/login", login_data)
    print_status("Login with Deactivated Account", response)
    assert response.status_code == 401

    # PHASE 4: Password Management
    print("\n\n#####################################")
    print("#  PHASE 4: PASSWORD MANAGEMENT  #")
    print("#####################################")

    # Test 12: Admin changes own password
    print("Test 4.1: Admin changing own password...")
    password_change_data = {
        "old_password": TEST_ADMIN_DATA["password"],
        "new_password": "new_admin_password_123!",
    }
    response = make_request(
        "PUT",
        f"/users/{admin_user_id}/password",
        password_change_data,
        token_type="Bearer",
        token=admin_access_token,
    )
    print_status("Admin Change Password", response)
    assert response.status_code == 200

    # Test 13: Request password reset for a non-existent email
    print(
        "Test 4.2: Requesting password reset for non-existent email (should give generic message)..."
    )
    response = make_request(
        "POST", "/forgot-password", {"email": "nonexistent@example.com"}
    )
    print_status("Forgot Password (non-existent email)", response)
    assert response.status_code == 200
    assert "If an account with that email exists" in response.json()["message"]

    # Test 14: Request password reset for admin user
    print("Test 4.3: Requesting password reset for admin user...")
    response = make_request(
        "POST", "/forgot-password", {"email": TEST_ADMIN_DATA["email"]}
    )
    print_status("Forgot Password (admin user)", response)
    assert response.status_code == 200

    # NOTE: The reset token will be printed in your Flask server's terminal!
    # You must copy it and paste it here for the next test.
    reset_token = input(
        "\n[ACTION REQUIRED]: Copy the password reset token from your Flask terminal and paste it here: "
    )

    # Test 15: Reset password with the token
    print("Test 4.4: Resetting admin's password with the token...")
    reset_data = {
        "token": reset_token,
        "new_password": TEST_ADMIN_DATA[
            "password"
        ],  # Resetting it back to the original
    }
    response = make_request("POST", "/reset-password", reset_data)
    print_status("Reset Password", response)
    assert response.status_code == 200

    # Test 16: Login with the new (reset) password
    print("Test 4.5: Logging in as admin with the reset password...")
    login_data = {
        "username_or_email": TEST_ADMIN_DATA["email"],
        "password": TEST_ADMIN_DATA["password"],
    }
    response = make_request("POST", "/login", login_data)
    print_status("Login with Reset Password", response)
    assert response.status_code == 200
    admin_access_token = response.json()["access_token"]  # Get new token
    admin_refresh_token = response.json()["refresh_token"]

    # PHASE 5: Access & Refresh Token Flow
    print("\n\n#####################################################")
    print("#  PHASE 5: ACCESS & REFRESH TOKEN FLOW (ADVANCED)  #")
    print("#####################################################")

    # This test requires a short token expiration (e.g., 1 minute in .env)
    print("Test 5.1: Waiting for access token to expire (1 minute)...")
    time.sleep(65)  # Wait for 65 seconds

    # Test 17: Attempt protected endpoint with expired token
    print("Test 5.2: Attempting to access profile with an expired access token...")
    response = make_request(
        "GET", f"/users/{admin_user_id}", token_type="Bearer", token=admin_access_token
    )
    print_status("Expired Token Access", response)
    assert response.status_code == 401

    # Test 18: Use refresh token to get new tokens
    print("Test 5.3: Using refresh token to get a new token pair...")
    response = make_request("POST", "/refresh", {"refresh_token": admin_refresh_token})
    print_status("Refresh Token", response)
    assert response.status_code == 200
    new_admin_access_token = response.json()["access_token"]
    new_admin_refresh_token = response.json()["refresh_token"]

    # Test 19: Use the new access token
    print("Test 5.4: Accessing profile with the newly refreshed access token...")
    response = make_request(
        "GET",
        f"/users/{admin_user_id}",
        token_type="Bearer",
        token=new_admin_access_token,
    )
    print_status("Access with New Token", response)
    assert response.status_code == 200

    # Test 20: Test logout
    print("Test 5.5: Logging out by revoking the refresh token...")
    response = make_request(
        "POST",
        "/logout",
        {"refresh_token": new_admin_refresh_token},
        token_type="Bearer",
        token=new_admin_access_token,
    )
    print_status("Logout", response)
    assert response.status_code == 200

    # Test 21: Old refresh token should now be invalid
    print("Test 5.6: Attempting to use the revoked refresh token (should fail)...")
    response = make_request(
        "POST", "/refresh", {"refresh_token": new_admin_refresh_token}
    )
    print_status("Use Revoked Refresh Token", response)
    assert response.status_code == 401


if __name__ == "__main__":
    # --- Instructions ---
    # 1. Ensure your Flask server is running in another terminal.
    # 2. For Phase 5, set ACCESS_TOKEN_EXPIRE_MINUTES to 1 in your .env file and restart the server.
    # 3. For Phase 4, keep an eye on your Flask terminal to copy the password reset token.
    print("Starting API tests. Please ensure your Flask server is running.")
    run_tests()
    print("\nAll tests completed.")
