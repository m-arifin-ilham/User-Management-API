# User Management RESTful API

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-lightgray.svg?logo=flask)](https://flask.palletsprojects.com/)
[![SQLite](https://img.shields.io/badge/Database-SQLite-blue.svg?logo=sqlite&logoColor=white)](https://www.sqlite.org/index.html)
[![GitHub](https://img.shields.io/badge/GitHub-Repo-brightgreen?style=flat&logo=github)](https://github.com/m-arifin-ilham/User-Management-API)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview
This project is a robust and secure RESTful API for managing user accounts. Built with **Flask** and **SQLite**, it serves as a foundational backend service for any web or mobile application. The API demonstrates a modern authentication flow using **short-lived access tokens** and **long-lived refresh tokens**, alongside secure password management and role-based authorization. The codebase is structured following the **SOLID principles** to ensure maintainability, scalability, and clean separation of concerns.

## Features
- 👤 **Secure User Authentication:** Supports user registration, login, and token-based access control.

- 🔑 **Access & Refresh Tokens:** Implements a professional authentication pattern using short-lived access tokens and long-lived, revokable refresh tokens.

- 🔒 **Role-Based Authorization:** Distinguishes between regular users and administrators, restricting access to sensitive endpoints.

- 🔐 **Password Management:** Secure password hashing (using Bcrypt), self-service password changes, and a robust forgot-password flow.

- 👥 **User Management:** Admin-level endpoints to view all users, update user details, and perform soft deletion (deactivating accounts).

- ⚙️ **Search & Pagination:** Efficiently handles large datasets with dynamic filtering and pagination for retrieving user lists.

- 📐 **Clean Architecture:** Organized into distinct API, Service, and Repository layers, adhering to SOLID principles for a clean and scalable design.

## Architectural Design
The project is structured in a layered architecture to separate responsibilities and manage dependencies effectively.

- **API Layer (`app.py`)**: The entry point of the application. It handles HTTP requests, calls the appropriate service methods, and formats responses. It contains no business logic or database queries.

- **Service Layer (`services.py`):** The core business logic. It orchestrates actions, performs validation, and uses the Repository layer to interact with the database. It is independent of the web framework.

- **Repository Layer (`repositories.py`):** The data access layer. It abstracts all database-specific operations, providing a clean interface for the services to read from and write to the database.

## Technologies Used
- **Python:** The core programming language.

- **Flask:** The web framework for building the API endpoints.

- **SQLite:** A lightweight, serverless database for persistent data storage.

- **Flask-Bcrypt:** For secure password hashing and verification.

- **PyJWT:** For generating, encoding, and decoding JSON Web Tokens.

- **python-dotenv:** To manage environment variables and keep sensitive data out of the codebase.

- **secrets:** Python's built-in module for generating cryptographically secure tokens.

## Getting Started
Follow these instructions to set up and run the project locally.

### Prerequisites
- Python 3.8+ installed on your system.

### Installation
1.  **Clone the repository:**

    ```
    git clone https://github.com/m-arifin-ilham/User-Management-API
    cd user_management_api
    ```

2.  **Set up a Python virtual environment:**

    ```
    python -m venv venv
    # On Windows:
    .\venv\Scripts\activate
    # On macOS/Linux:
    source venv/bin/activate
    ```

3.  **Install dependencies:**

    ```
    pip install -r requirements.txt
    ```

4.  **Configure environment variables:**
    Create a file named `.env` in the project root with the following content. **Remember to replace the placeholder values with long, randomly generated strings.**

    ```
    SECRET_KEY='your_flask_secret_key_change_me'
    JWT_SECRET_KEY='your_jwt_secret_key_change_me_too'
    ```

5.  **Initialize the database:**
    This command will create the `users.db` file and populate it with a default admin user.

    ```
    python database.py
    ```

### Running the API
Ensure your virtual environment is active, then run the Flask application:

```
# Set the FLASK_APP environment variable:
# On Windows: set FLASK_APP=app.py
# On macOS/Linux: export FLASK_APP=app.py

# Start the development server:
flask run
```

The API will be accessible at `http://127.0.0.1:5000`.

## API Endpoints
All endpoints assume a base URL of `http://127.0.0.1:5000`. Protected endpoints require an `Authorization: Bearer <access_token>` header. For `POST` and `PUT` requests, the `Content-Type` header should be `application/json`.

### Authentication & Token Management
| Method | Endpoint           | Description                                                                      |
| :----- | :----------------- | :------------------------------------------------------------------------------- |
| `POST` | `/register`        | Creates a new user account.                                                      |
| `POST` | `/login`           | Authenticates a user and returns an **access token** and a **refresh token**.    |
| `POST` | `/refresh`         | Exchanges a valid **refresh token** for a new pair of access and refresh tokens. |
| `POST` | `/logout`          | Revokes a user's refresh token, logging them out.                                |
| `POST` | `/forgot-password` | Initiates the password reset flow by generating a token.                         |
| `POST` | `/reset-password`  | Resets a user's password using a valid reset token.                              |

### User CRUD (Protected Endpoints)
| Method   | Endpoint                    | Description                                                                         |
| :------- | :-------------------------- | :---------------------------------------------------------------------------------- |
| `GET`    | `/users`                    | **(Admin Only)** Retrieves a paginated list of all users. Support filtering.        |
| `GET`    | `/users/{user_id}`          | Retrieves a single user's profile. **(User can only see own profile unless admin)** |
| `PUT`    | `/users/{user_id}`          | Updates a user's profile. **(User can only update own profile unless admin)**       |
| `PUT`    | `/users/{user_id}/password` | Allows a logged-in user to change their own password.                               |
| `DELETE` | `/users/{user_id}`          | **(Admin Only)** Deactivates a user's account (soft delete).                        |

## How to Run Tests
A comprehensive test script is included to validate the API's functionality, including authentication flows, authorization rules, and error handling.
1.  Ensure the Flask server is running in one terminal.

2.  Open a second terminal, activate the virtual environment, and run:

    ```
    python test_api.py
    ```

    The script will guide you through the tests, including a step where you need to copy the password reset token from the Flask server's output.

## Future Enhancements
- **Email Service Integration:** Integrate with a mail service (e.g., SendGrid, Mailgun) to actually send password reset emails.

- **Dockerization:** Containerize the application using Docker for easier deployment and environment consistency.

- **PostgreSQL Integration:** Add a new repository (`PostgreSQLUserRepository`) to demonstrate seamless database swapping without changing the service layer.

- **API Documentation:** Use a tool like `Flask-RESTful-Swagger` to automatically generate interactive API documentation.

- **Unit & Integration Tests:** Implement a formal test suite with a framework like `pytest`.

## License
This project is licensed under the MIT License.

---

*Developed by [Muhammad Arifin Ilham](https://www.linkedin.com/in/arifin-ilham-at-ska/)* 

*Current Date: August 1, 2025*