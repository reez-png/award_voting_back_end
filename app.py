# Import necessary Flask components and other libraries
from flask import Flask, jsonify, request, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os
import jwt
from functools import wraps
import datetime
import uuid
import logging # Import logging module
from flask_cors import CORS # NEW: Import Flask-CORS
from waitress import serve

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Initialize the Flask application
app = Flask(__name__)

CORS(app) # Allows CORS for all routes and all origins for development simplicity

# Configure the secret key for JWT signing from environment variables
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')
if not app.config['SECRET_KEY']:
    raise RuntimeError("SECRET_KEY not set in .env file. Please generate a strong secret key.")

# Configure the database URI from DATABASE_URL (e.g. on Heroku) or fall back to SQLite
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL',
    'sqlite:///site.db'
)

# Disable SQLAlchemy event tracking for performance
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize the SQLAlchemy instance
db = SQLAlchemy(app)

# --- Basic Logging Configuration ---
# Set up a basic logger for the application
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
# --- End Logging Configuration ---

# --- Database Models ---
class User(db.Model):
    """
    Defines the User model for our database.
    Each instance of this class will correspond to a row in the 'user' table.
    """
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), default='user', nullable=False)
    vote_balance = db.Column(db.Integer, default=0, nullable=False)

    # Relationship to Votes. A user can cast many votes.
    votes = db.relationship('Vote', backref='voter', lazy=True)
    transactions = db.relationship('Transaction', backref='buyer', lazy=True)

    def __repr__(self):
        """
        Provides a string representation of the User object,
        useful for debugging.
        """
        return f'<User {self.username}>'

    def set_password(self, password):
        """
        Hashes the provided plain-text password and stores it in password_hash.
        """
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """
        Checks if the provided plain-text password matches the stored hash.
        """
        return check_password_hash(self.password_hash, password)


class Category(db.Model):
    """
    Defines the Category model. Each instance is an awards category (e.g., 'Best Actor').
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=True)

    # Define a relationship to the Nominee model.
    nominees = db.relationship('Nominee', backref='category', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Category {self.name}>'


class Nominee(db.Model):
    """
    Defines the Nominee model. Each instance is an individual nominated person/item.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    photo_url = db.Column(db.String(255), nullable=True)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)

    # Vote count is kept on the Nominee model for quick aggregation,
    # but actual votes are stored in the Vote table for detailed history/auditing.
    vote_count = db.Column(db.Integer, default=0, nullable=False)

    # Relationship to Votes. A nominee can receive many votes.
    received_votes = db.relationship('Vote', backref='nominee', lazy=True, cascade="all, delete-orphan")

    def __repr__(self):
        return f'<Nominee {self.name} in Category {self.category.name if self.category else "N/A"}>'


# Vote Model
class Vote(db.Model):
    """
    Defines the Vote model to record each individual vote cast.
    This provides an audit trail for voting.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    nominee_id = db.Column(db.Integer, db.ForeignKey('nominee.id'), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    is_paid_vote = db.Column(db.Boolean, default=True, nullable=False)

    def __repr__(self):
        return f'<Vote from User {self.user_id} for Nominee {self.nominee_id} at {self.timestamp}>'
# --- End Database Models ---

# --- AwardSetting Model ---
class AwardSetting(db.Model):
    """
    Defines a model for general award show settings, allowing dynamic control.
    Example settings: 'voting_active', 'show_live_rankings', 'voting_start_time', 'voting_end_time'.
    """
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(100), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=True)
    description = db.Column(db.String(255), nullable=True)

    def __repr__(self):
        return f'<AwardSetting {self.key}: {self.value}>'

# --- End Database Models ---

# ---Transaction Model----
class Transaction(db.Model):
    """
    Defines the Transaction model to record payment attempts for vote packs.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount_cedis = db.Column(db.Float, nullable=False)
    votes_to_add = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow, nullable=False)
    status = db.Column(db.String(50), default='PENDING', nullable=False)
    payment_gateway_ref = db.Column(db.String(255), unique=True, nullable=True)

    def __repr__(self):
        return f'<Transaction {self.id} for User {self.user_id} - {self.amount_cedis} GHS, Status: {self.status}>'


# --- End Database Models ---

# --- Database Initialization ---
with app.app_context():
    db.create_all()
    # Initialize default settings if they don't exist
    if not AwardSetting.query.filter_by(key='voting_active').first():
        db.session.add(
            AwardSetting(key='voting_active', value='true', description='Is voting currently active? (true/false)'))
    if not AwardSetting.query.filter_by(key='show_live_rankings').first():
        db.session.add(AwardSetting(key='show_live_rankings', value='false',
                                    description='Should live rankings be visible to public? (true/false)'))
    if not AwardSetting.query.filter_by(key='voting_start_time').first():
        db.session.add(AwardSetting(key='voting_start_time', value=datetime.datetime.utcnow().isoformat(),
                                    description='Start time for voting (ISO format)'))
    if not AwardSetting.query.filter_by(key='voting_end_time').first():
        future_date = datetime.datetime.utcnow() + datetime.timedelta(days=365)
        db.session.add(AwardSetting(key='voting_end_time', value=future_date.isoformat(),
                                    description='End time for voting (ISO format)'))
    db.session.commit()

# --- End Database Initialization ---

# --- Authentication Decorators ---
def token_required(f):
    """
    Decorator function to enforce JWT authentication on routes.
    It checks for a valid JWT in the request header.
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        if not token:
            logger.warning("Attempt to access token_required route without token.")  # NEW: Logging
            return jsonify({'message': 'Token is missing!'}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
            if not current_user:
                logger.warning(
                    f"Invalid token or user not found for public_id: {data.get('public_id')}")  # NEW: Logging
                return jsonify({'message': 'Token is invalid or user not found!'}), 401
        except jwt.ExpiredSignatureError:
            logger.warning("Attempt to access token_required route with expired token.")  # NEW: Logging
            return jsonify({'message': 'Token has expired!'}), 401
        except jwt.InvalidTokenError:
            logger.error("Attempt to access token_required route with invalid token.", exc_info=True)  # NEW: Logging
            return jsonify({'message': 'Token is invalid!'}), 401
        except Exception as e:
            logger.exception("An unexpected error occurred during token validation.")  # NEW: Logging
            return jsonify({'message': 'An error occurred during token validation!'}), 500
        kwargs['current_user'] = current_user
        return f(*args, **kwargs)

    return decorated


def admin_required(f):
    """
    Decorator function to enforce that only users with the 'admin' role
    can access the decorated route.
    It relies on the token_required decorator to first authenticate the user.
    """

    @wraps(f)
    @token_required
    def decorated_admin(*args, **kwargs):
        current_user = kwargs.get('current_user')
        if not current_user or current_user.role != 'admin':
            logger.warning(
                f"Unauthorized admin access attempt by user: {current_user.username if current_user else 'unknown'}")  # NEW: Logging
            return jsonify({'message': 'Admin access required!'}), 403
        return f(*args, **kwargs)

    return decorated_admin
# --- End Authentication Decorators ---

# --- Centralized Error Handlers ---
@app.errorhandler(400)
def bad_request(error):
    logger.error(f"Bad Request: {request.url} - {request.data.decode('utf-8') if request.data else 'No data'}") # Logging
    return jsonify({"message": "Bad request. Please check your input."}), 400

@app.errorhandler(404)
def not_found(error):
    logger.warning(f"Not Found: {request.url}") # Logging
    return jsonify({"message": "Resource not found."}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    logger.warning(f"Method Not Allowed: {request.method} {request.url}") # Logging
    return jsonify({"message": "Method not allowed for this URL."}), 405

@app.errorhandler(500)
def internal_server_error(error):
    # This captures unhandled exceptions. In production, you'd log error details securely.
    logger.exception("Internal Server Error occurred.") # Logging: logs traceback automatically
    return jsonify({"message": "An unexpected error occurred on the server."}), 500
# --- End Centralized Error Handlers ---


# --- API Routes ---
@app.route('/')
def home():
    logger.info("Home route accessed.") # Logging
    return jsonify({"message": "Welcome to the Awards Voting Backend!"})

@app.route('/api/status')
def status():
    logger.info("Status check performed.") # Logging
    return jsonify({"status": "API is up and running!"})

@app.route('/api/register', methods=['POST'])
def register():
    # NEW: Input validation for JSON type moved to global handler, but still check here for specific data.
    if not request.is_json:
        # This will be caught by @app.errorhandler(400) if content-type is wrong
        return jsonify({"message": "Request must be JSON"}), 400 # Still explicit here for clarity

    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    # More robust input validation
    if not username or not isinstance(username, str) or not (3 <= len(username) <= 80):
        logger.warning(f"Invalid username during registration: {username}")
        return jsonify({"message": "Username is required and must be 3-80 characters long."}), 400
    if not email or not isinstance(email, str) or '@' not in email or '.' not in email:  # Basic email format check
        logger.warning(f"Invalid email during registration: {email}")
        return jsonify({"message": "Valid email is required."}), 400
    if not password or not isinstance(password, str) or not (6 <= len(password) <= 128):  # Password length check
        logger.warning("Invalid password length during registration.")
        return jsonify({"message": "Password is required and must be at least 6 characters long."}), 400

    if User.query.filter_by(username=username).first():
        logger.info(f"Registration failed: Username '{username}' already exists.")
        return jsonify({"message": "Username already exists"}), 409
    if User.query.filter_by(email=email).first():
        logger.info(f"Registration failed: Email '{email}' already exists.")
        return jsonify({"message": "Email already exists"}), 409

    new_user = User(username=username, email=email)
    new_user.set_password(password)

    try:
        db.session.add(new_user)
        db.session.commit()
        logger.info(f"User '{username}' registered successfully with public_id: {new_user.public_id}")
        return jsonify(
            {"message": "User registered successfully!", "user_id": new_user.id, "public_id": new_user.public_id,
             "vote_balance": new_user.vote_balance}), 201
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error during registration for user '{username}'.")  # NEW: Log exception details
        return jsonify({"message": "Something went wrong during registration"}), 500


@app.route('/api/login', methods=['POST'])
def login():
    """
    Handles user login.
    Expects JSON input with 'username' and 'password'.
    Returns a JWT if credentials are valid.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Input validation
    if not username or not isinstance(username, str) or not password or not isinstance(password, str):
        logger.warning("Login attempt with missing or invalid username/password data types.")
        return jsonify({"message": "Username and password are required."}), 400

    user = User.query.filter_by(username=username).first()

    if not user or not user.check_password(password):
        logger.info(f"Login failed for username '{username}': Invalid credentials.")
        return jsonify({"message": "Invalid credentials"}), 401

    token_payload = {
        'public_id': user.public_id,
        'role': user.role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
    }
    token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
    logger.info(f"User '{username}' logged in successfully.")
    return jsonify({'token': token}), 200


@app.route('/api/protected', methods=['GET'])
@token_required
def protected_route(**kwargs):
    current_user = kwargs.get('current_user')
    logger.info(f"User '{current_user.username}' accessed protected route.")
    return jsonify({
        'message': 'You accessed a protected route!',
        'user_public_id': current_user.public_id,
        'user_username': current_user.username,
        'user_role': current_user.role,
        'user_vote_balance': current_user.vote_balance
    }), 200


# --- User Profile Management Endpoint ---
@app.route('/api/user/profile', methods=['PUT'])
@token_required
def update_user_profile(**kwargs):
    current_user = kwargs.get('current_user')

    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    new_username = data.get('username')
    new_email = data.get('email')
    old_password = data.get('old_password')  # Required for password changes
    new_password = data.get('new_password')  # New password value

    changes_made = False

    # Handle username update
    if new_username is not None:
        if not isinstance(new_username, str) or not (3 <= len(new_username) <= 80):
            logger.warning(f"Invalid new username format for user {current_user.username}: {new_username}")
            return jsonify({"message": "Username must be 3-80 characters long."}), 400
        if new_username != current_user.username:
            if User.query.filter_by(username=new_username).first():
                logger.info(
                    f"Username update failed for user {current_user.username}: New username '{new_username}' already exists.")
                return jsonify({"message": "New username already taken."}), 409
            current_user.username = new_username
            changes_made = True
            logger.info(f"User {current_user.public_id} updated username to {new_username}.")

    # Handle email update
    if new_email is not None:
        if not isinstance(new_email, str) or '@' not in new_email or '.' not in new_email:
            logger.warning(f"Invalid new email format for user {current_user.username}: {new_email}")
            return jsonify({"message": "Valid email format is required."}), 400
        if new_email != current_user.email:
            if User.query.filter_by(email=new_email).first():
                logger.info(
                    f"Email update failed for user {current_user.username}: New email '{new_email}' already exists.")
                return jsonify({"message": "New email already taken."}), 409
            current_user.email = new_email
            changes_made = True
            logger.info(f"User {current_user.public_id} updated email to {new_email}.")

    # Handle password update
    if new_password is not None:
        if not old_password:
            logger.warning(f"Password change attempted by user {current_user.username} without old_password.")
            return jsonify({"message": "Current password is required to change password."}), 400
        if not isinstance(new_password, str) or not (6 <= len(new_password) <= 128):
            logger.warning(f"Invalid new password length for user {current_user.username}.")
            return jsonify({"message": "New password must be at least 6 characters long."}), 400

        if not current_user.check_password(old_password):
            logger.info(f"Password change failed for user {current_user.username}: Invalid current password.")
            return jsonify({"message": "Incorrect current password."}), 401  # Unauthorized

        current_user.set_password(new_password)
        changes_made = True
        logger.info(f"User {current_user.public_id} successfully changed password.")

    if not changes_made:
        return jsonify({
                           "message": "No changes provided or changes are identical to current values."}), 200  # Or 400 if you want to force change

    try:
        db.session.commit()
        return jsonify({
            "message": "Profile updated successfully!",
            "user": {
                "public_id": current_user.public_id,
                "username": current_user.username,
                "email": current_user.email
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating profile for user {current_user.username}.")
        return jsonify({"message": "Something went wrong updating profile"}), 500
# --- End User Profile Management Endpoint ---


# --- Category Management API Endpoints (Admin Only) ---
@app.route('/api/categories', methods=['POST'])
@admin_required
def create_category(**kwargs):
    """
    Creates a new category. Admin only.
    Expects JSON input with 'name' and optionally 'description'.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')

    # Input validation
    if not name or not isinstance(name, str) or not (3 <= len(name) <= 100):
        logger.warning(f"Invalid category name during creation: {name}")
        return jsonify({"message": "Category name is required and must be 3-100 characters long."}), 400
    if description is not None and (not isinstance(description, str) or len(description) > 255):
        logger.warning(f"Invalid category description during creation for name '{name}'.")
        return jsonify({"message": "Category description must be a string up to 255 characters."}), 400

    if Category.query.filter_by(name=name).first():
        logger.info(f"Category creation failed: Name '{name}' already exists.")
        return jsonify({"message": "Category with this name already exists"}), 409

    new_category = Category(name=name, description=description)

    try:
        db.session.add(new_category)
        db.session.commit()
        logger.info(f"Category '{name}' created successfully.")
        return jsonify({
            "message": "Category created successfully!",
            "category_id": new_category.id,
            "name": new_category.name
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error creating category '{name}'.")
        return jsonify({"message": "Something went wrong creating category"}), 500


@app.route('/api/categories', methods=['GET'])
def get_all_categories():
    categories = Category.query.all()
    output = []
    for category in categories:
        output.append({
            'id': category.id,
            'name': category.name,
            'description': category.description
        })
    logger.info("All categories retrieved.")
    return jsonify({"categories": output}), 200

@app.route('/api/categories/<int:category_id>', methods=['GET'])
def get_single_category(category_id):
    category = Category.query.get(category_id)
    if not category:
        logger.warning(f"Attempt to retrieve non-existent category with ID: {category_id}")
        return jsonify({"message": "Category not found"}), 404
    logger.info(f"Category '{category.name}' (ID: {category_id}) retrieved.")
    return jsonify({
        'id': category.id,
        'name': category.name,
        'description': category.description
    }), 200


@app.route('/api/categories/<int:category_id>', methods=['PUT'])
@admin_required
def update_category(category_id, **kwargs):
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    category = Category.query.get(category_id)
    if not category:
        logger.warning(f"Attempt to update non-existent category with ID: {category_id}")
        return jsonify({"message": "Category not found"}), 404

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')

    # Input validation for update
    if name:
        if not isinstance(name, str) or not (3 <= len(name) <= 100):
            logger.warning(f"Invalid new category name during update for ID {category_id}: {name}")
            return jsonify({"message": "Category name must be 3-100 characters long."}), 400
        existing_category = Category.query.filter_by(name=name).first()
        if existing_category and existing_category.id != category_id:
            logger.info(
                f"Category update failed for ID {category_id}: Name '{name}' already exists for another category.")
            return jsonify({"message": "Category with this name already exists"}), 409
        category.name = name
    if description is not None:
        if not isinstance(description, str) or len(description) > 255:
            logger.warning(f"Invalid category description during update for ID {category_id}.")
            return jsonify({"message": "Category description must be a string up to 255 characters."}), 400
        category.description = description

    try:
        db.session.commit()
        logger.info(f"Category '{category.name}' (ID: {category_id}) updated successfully.")
        return jsonify({"message": "Category updated successfully!", "category": {
            'id': category.id,
            'name': category.name,
            'description': category.description
        }}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating category (ID: {category_id}).")
        return jsonify({"message": "Something went wrong updating category"}), 500


@app.route('/api/categories/<int:category_id>', methods=['DELETE'])
@admin_required
def delete_category(category_id, **kwargs):
    category = Category.query.get(category_id)
    if not category:
        logger.warning(f"Attempt to delete non-existent category with ID: {category_id}")
        return jsonify({"message": "Category not found"}), 404
    try:
        db.session.delete(category)
        db.session.commit()
        logger.info(f"Category '{category.name}' (ID: {category_id}) deleted successfully.")
        return jsonify({"message": "Category deleted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error deleting category (ID: {category_id}).")
        return jsonify({"message": "Something went wrong deleting category"}), 500


# --- Nominee Management API Endpoints (Admin Only) ---
@app.route('/api/nominees', methods=['POST'])
@admin_required
def create_nominee(**kwargs):
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    name = data.get('name')
    category_id = data.get('category_id')
    description = data.get('description')
    photo_url = data.get('photo_url')

    # Input validation for nominee creation
    if not name or not isinstance(name, str) or not (3 <= len(name) <= 100):
        logger.warning(f"Invalid nominee name during creation: {name}")
        return jsonify({"message": "Nominee name is required and must be 3-100 characters long."}), 400
    if not category_id or not isinstance(category_id, int) or category_id <= 0:
        logger.warning(f"Invalid category_id during nominee creation: {category_id}")
        return jsonify({"message": "Valid category ID is required."}), 400
    if description is not None and (
            not isinstance(description, str) or len(description) > 5000):  # Allow longer text for description
        logger.warning(f"Invalid nominee description during creation for name '{name}'.")
        return jsonify({"message": "Nominee description must be a string up to 5000 characters."}), 400
    if photo_url is not None and (
            not isinstance(photo_url, str) or not photo_url.startswith('http')):  # Basic URL check
        logger.warning(f"Invalid nominee photo_url during creation for name '{name}'.")
        return jsonify({"message": "Photo URL must be a valid URL string."}), 400

    category = Category.query.get(category_id)
    if not category:
        logger.warning(f"Nominee creation failed: Category with ID {category_id} not found.")
        return jsonify({"message": "Category not found"}), 404

    if Nominee.query.filter_by(name=name, category_id=category_id).first():
        logger.info(f"Nominee creation failed: Nominee '{name}' already exists in category {category_id}.")
        return jsonify({"message": f"Nominee '{name}' already exists in this category"}), 409

    new_nominee = Nominee(
        name=name,
        description=description,
        photo_url=photo_url,
        category_id=category_id
    )

    try:
        db.session.add(new_nominee)
        db.session.commit()
        logger.info(f"Nominee '{name}' created successfully in category {category.name}.")
        return jsonify({
            "message": "Nominee created successfully!",
            "nominee_id": new_nominee.id,
            "name": new_nominee.name,
            "category": category.name
        }), 201
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error creating nominee '{name}'.")
        return jsonify({"message": "Something went wrong creating nominee"}), 500


@app.route('/api/nominees', methods=['GET'])
def get_all_nominees():
    category_id = request.args.get('category_id', type=int)

    nominees_query = Nominee.query

    if category_id:
        category = Category.query.get(category_id)
        if not category:
            logger.warning(f"Attempt to retrieve nominees for non-existent category with ID: {category_id}")
            return jsonify({"message": "Category not found"}), 404
        nominees_query = nominees_query.filter_by(category_id=category_id)

    nominees = nominees_query.all()
    output = []
    for nominee in nominees:
        output.append({
            'id': nominee.id,
            'name': nominee.name,
            'description': nominee.description,
            'photo_url': nominee.photo_url,
            'category_id': nominee.category_id,
            'category_name': nominee.category.name if nominee.category else None,
            'vote_count': nominee.vote_count
        })
    logger.info(f"Retrieved {len(nominees)} nominees (filtered by category_id: {category_id or 'None'}).")
    return jsonify({"nominees": output}), 200


@app.route('/api/nominees/<int:nominee_id>', methods=['GET'])
def get_single_nominee(nominee_id):
    nominee = Nominee.query.get(nominee_id)
    if not nominee:
        logger.warning(f"Attempt to retrieve non-existent nominee with ID: {nominee_id}")
        return jsonify({"message": "Nominee not found"}), 404
    logger.info(f"Nominee '{nominee.name}' (ID: {nominee_id}) retrieved.")
    return jsonify({
        'id': nominee.id,
        'name': nominee.name,
        'description': nominee.description,
        'photo_url': nominee.photo_url,
        'category_id': nominee.category_id,
        'category_name': nominee.category.name if nominee.category else None,
        'vote_count': nominee.vote_count
    }), 200

@app.route('/api/nominees/<int:nominee_id>', methods=['PUT'])
@admin_required
def update_nominee(nominee_id, **kwargs):
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    nominee = Nominee.query.get(nominee_id)
    if not nominee:
        logger.warning(f"Attempt to update non-existent nominee with ID: {nominee_id}")
        return jsonify({"message": "Nominee not found"}), 404

    data = request.get_json()
    name = data.get('name')
    description = data.get('description')
    photo_url = data.get('photo_url')
    new_category_id = data.get('category_id')

    # Input validation for nominee update
    if name:
        if not isinstance(name, str) or not (3 <= len(name) <= 100):
            logger.warning(f"Invalid new nominee name during update for ID {nominee_id}: {name}")
            return jsonify({"message": "Nominee name must be 3-100 characters long."}), 400
        existing_nominee = Nominee.query.filter_by(name=name, category_id=nominee.category_id).first()
        if existing_nominee and existing_nominee.id != nominee_id:
            logger.info(
                f"Nominee update failed for ID {nominee_id}: Name '{name}' already exists in category {nominee.category_id}.")
            return jsonify({"message": f"Nominee '{name}' already exists in this category"}), 409
        nominee.name = name

    if new_category_id:
        if not isinstance(new_category_id, int) or new_category_id <= 0:
            logger.warning(f"Invalid new category_id during nominee update for ID {nominee_id}: {new_category_id}")
            return jsonify({"message": "Valid category ID is required for transfer."}), 400
        new_category = Category.query.get(new_category_id)
        if not new_category:
            logger.warning(
                f"Nominee update failed for ID {nominee_id}: New category with ID {new_category_id} not found.")
            return jsonify({"message": "New category not found"}), 404
        nominee.category_id = new_category_id

    if description is not None:
        if not isinstance(description, str) or len(description) > 5000:
            logger.warning(f"Invalid nominee description during update for ID {nominee_id}.")
            return jsonify({"message": "Nominee description must be a string up to 5000 characters."}), 400
        nominee.description = description
    if photo_url is not None:
        if not isinstance(photo_url, str) or (
                photo_url and not photo_url.startswith('http')):  # Allow empty string to clear URL
            logger.warning(f"Invalid nominee photo_url during update for ID {nominee_id}.")
            return jsonify({"message": "Photo URL must be a valid URL string or empty."}), 400
        nominee.photo_url = photo_url

    try:
        db.session.commit()
        logger.info(f"Nominee '{nominee.name}' (ID: {nominee_id}) updated successfully.")
        return jsonify({"message": "Nominee updated successfully!", "nominee": {
            'id': nominee.id,
            'name': nominee.name,
            'description': nominee.description,
            'photo_url': nominee.photo_url,
            'category_id': nominee.category_id,
            'category_name': nominee.category.name if nominee.category else None,
            'vote_count': nominee.vote_count
        }}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating nominee (ID: {nominee_id}).")
        return jsonify({"message": "Something went wrong updating nominee"}), 500


@app.route('/api/nominees/<int:nominee_id>', methods=['DELETE'])
@admin_required
def delete_nominee(nominee_id, **kwargs):
    nominee = Nominee.query.get(nominee_id)
    if not nominee:
        logger.warning(f"Attempt to delete non-existent nominee with ID: {nominee_id}")
        return jsonify({"message": "Nominee not found"}), 404
    try:
        db.session.delete(nominee)
        db.session.commit()
        logger.info(f"Nominee '{nominee.name}' (ID: {nominee_id}) deleted successfully.")
        return jsonify({"message": "Nominee deleted successfully!"}), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error deleting nominee (ID: {nominee_id}).")
        return jsonify({"message": "Something went wrong deleting nominee"}), 500

# --- Vote Casting and Monetization Endpoints ---
# Endpoint to get current user's vote balance and history
@app.route('/api/user/votes', methods=['GET'])
@token_required
def get_user_vote_info(**kwargs):
    """
    Retrieves the authenticated user's current vote balance and their voting history.
    """
    current_user = kwargs.get('current_user')

    # Fetch user's vote balance
    vote_balance = current_user.vote_balance

    # Fetch user's vote history
    # We fetch votes associated with the user and order by timestamp descending
    user_votes = Vote.query.filter_by(user_id=current_user.id).order_by(Vote.timestamp.desc()).all()
    vote_history_output = []
    for vote in user_votes:
        # To get the nominee and category names, we need to access the relationships.
        # This will trigger additional database queries if not already loaded (lazy loading).
        nominee_name = vote.nominee.name if vote.nominee else 'N/A'
        category_name = vote.category.name if vote.category else 'N/A'
        vote_history_output.append({
            'vote_id': vote.id,
            'nominee_id': vote.nominee_id,
            'nominee_name': nominee_name,
            'category_id': vote.category_id,
            'category_name': category_name,
            'timestamp': vote.timestamp.isoformat(),  # Format datetime for JSON
            'is_paid_vote': vote.is_paid_vote
        })

        # Fetch user's transaction history
    user_transactions = Transaction.query.filter_by(user_id=current_user.id).order_by(Transaction.timestamp.desc()).all()
    transaction_history_output = []
    for transaction in user_transactions:
        transaction_history_output.append({
            'transaction_id': transaction.id,
            'amount_cedis': transaction.amount_cedis,
            'votes_to_add': transaction.votes_to_add,
            'timestamp': transaction.timestamp.isoformat(),
            'status': transaction.status,
            'payment_gateway_ref': transaction.payment_gateway_ref
        })

    logger.info(f"User '{current_user.username}' retrieved vote and transaction history.")
    return jsonify({
        "vote_balance": vote_balance,
        "vote_history": vote_history_output,
        "transaction_history": transaction_history_output
    }), 200

# Endpoint for users to initiate vote purchase
@app.route('/api/buy-votes', methods=['POST'])
@token_required
def initiate_vote_purchase(**kwargs):
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400
    """
    Initiates a vote purchase transaction.
    Instead of directly adding votes, it creates a PENDING transaction.
    Expects JSON input with 'amount_cedis' (e.g., price paidin GHS) and 'votes_to_add'.
    """
    current_user = kwargs.get('current_user')

    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()

    # 1. Extract the raw values
    raw_amount = data.get('amount_cedis')
    raw_votes = data.get('votes_to_add')

    # 2. Convert & validate types
    try:
        amount_cedis = float(raw_amount)
        votes_to_add = int(raw_votes)
    except (TypeError, ValueError):
        # non‐numeric or missing
        logger.warning(
            f"Conversion error during purchase initiation for user "
            f"{current_user.username}: amount_cedis={raw_amount}, votes_to_add={raw_votes}"
        )
        return jsonify({
            "message": "Both amount_cedis and votes_to_add must be valid numbers."
        }), 400

    # 3. Validate > 0
    if amount_cedis <= 0:
        logger.warning(
            f"Invalid amount_cedis during purchase initiation for user "
            f"{current_user.username}: {amount_cedis}"
        )
        return jsonify({"message": "Valid amount (Cedis) is required."}), 400

    if votes_to_add <= 0:
        logger.warning(
            f"Invalid votes_to_add during purchase initiation for user "
            f"{current_user.username}: {votes_to_add}"
        )
        return jsonify({"message": "Valid number of votes to add is required."}), 400

    new_transaction = Transaction(
        user_id=current_user.id,
        amount_cedis=amount_cedis,
        votes_to_add=votes_to_add,
        status='PENDING'  # Initial status is PENDING
    )

    try:
        db.session.add(new_transaction)
        db.session.commit()
        logger.info(
            f"User '{current_user.username}' initiated payment for {votes_to_add} votes (TxID: {new_transaction.id}).")
        return jsonify({
            "message": "Payment initiation successful. Please complete the payment.",
            "transaction_id": new_transaction.id,
            "status": new_transaction.status,
            "amount_to_pay": new_transaction.amount_cedis,
            "votes_expected": new_transaction.votes_to_add
        }), 202
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error initiating payment for user '{current_user.username}'.")
        return jsonify({"message": "Something went wrong initiating payment"}), 500

# Endpoint for payment gateway webhook/confirmation
@app.route('/api/payment/confirm', methods=['POST'])
def confirm_payment():
    """
    Endpoint to confirm a payment. In a real scenario, this would be a webhook
    from a payment gateway. For testing, you'll call this manually.
    Expects JSON input with 'transaction_id', 'status' (e.g., 'COMPLETED', 'FAILED'),
    and optionally 'payment_gateway_ref'.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    raw_txn_id = data.get('transaction_id')
    status = data.get('status')
    payment_gateway_ref = data.get('payment_gateway_ref')

    # 1) Cast and validate transaction_id
    try:
        transaction_id = int(raw_txn_id)
        if transaction_id <= 0:
            raise ValueError
    except (TypeError, ValueError):
        logger.warning(f"Invalid transaction_id during payment confirmation: {raw_txn_id}")
        return jsonify({"message": "Valid transaction ID is required."}), 400

    # 2) Validate status
    if not status or not isinstance(status, str) or status.upper() not in ['COMPLETED', 'FAILED', 'REFUNDED']:
        logger.warning(f"Invalid status for TxID {transaction_id}: {status}")
        return jsonify({"message": "Valid status (COMPLETED, FAILED, REFUNDED) is required."}), 400

    # 3) Validate payment_gateway_ref (optional)
    if payment_gateway_ref is not None and (not isinstance(payment_gateway_ref, str) or len(payment_gateway_ref) > 255):
        logger.warning(f"Invalid payment_gateway_ref for TxID {transaction_id}.")
        return jsonify({"message": "Payment gateway reference must be a string up to 255 characters."}), 400

    # 4) Load transaction
    transaction = Transaction.query.get(transaction_id)
    if not transaction:
        logger.warning(f"Transaction {transaction_id} not found.")
        return jsonify({"message": "Transaction not found"}), 404

    # 5) Prevent redundant or illegal transitions
    # Redundant COMPLETED confirmation
    if transaction.status == 'COMPLETED' and status.upper() == 'COMPLETED':
        logger.info(f"Redundant payment confirmation for already COMPLETED transaction {transaction_id}.")
        return jsonify({"message": f"Transaction already {transaction.status}."}), 409

    # COMPLETED can only go to REFUNDED
    if transaction.status == 'COMPLETED' and status.upper() not in ['REFUNDED']:
        logger.warning(f"Illegal transition {transaction.status} → {status.upper()} for TxID {transaction_id}.")
        return jsonify({"message": "Cannot change status of a completed transaction except to REFUNDED."}), 409

    # 6) Load user
    user = User.query.get(transaction.user_id)
    if not user:
        logger.error(f"Associated user not found for transaction {transaction_id} Data inconsistency!")
        return jsonify({"message": "Associated user not found for transaction."}), 500

    original_status = transaction.status

    # 7) Update inside try/except
    try:
        transaction.status = status.upper()
        if payment_gateway_ref:
            transaction.payment_gateway_ref = payment_gateway_ref

        if status.upper() == 'COMPLETED':
            # Only add votes on first COMPLETION or retry from FAILED
            if original_status in ['PENDING', 'FAILED']:
                user.vote_balance += transaction.votes_to_add
                logger.info(
                    f"Added {transaction.votes_to_add} votes to user {user.username}. New balance: {user.vote_balance}")
            else:
                logger.warning(f"No vote change for TxID {transaction_id}; original status was {original_status}.")
            db.session.commit()
            return jsonify({
                "message": f"Transaction {transaction_id} successfully COMPLETED. Votes added.",
                "user_id": user.id,
                "new_vote_balance": user.vote_balance
            }), 200

        elif status.upper() == 'FAILED':
            logger.info(f"Transaction {transaction_id} marked as FAILED.")
            db.session.commit()
            return jsonify({"message": f"Transaction {transaction_id} updated to FAILED."}), 200

        else:  # REFUNDED
            logger.info(f"Transaction {transaction_id} marked as REFUNDED.")
            # Note: vote deduction on refund not implemented
            db.session.commit()
            return jsonify(
                {"message": f"Transaction {transaction_id} status updated to REFUNDED. (Votes not deducted)"}), 200

    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error confirming payment for TxID {transaction_id}")
        return jsonify({"message": "Something went wrong confirming payment."}), 500


# Endpoint for casting a vote
@app.route('/api/vote', methods=['POST'])
@token_required
def cast_vote(**kwargs):
    current_user = kwargs.get('current_user')

    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()

    # 1) Cast and validate nominee_id
    raw_nominee_id = data.get('nominee_id')
    try:
        nominee_id = int(raw_nominee_id)
        if nominee_id <= 0:
            raise ValueError
    except (TypeError, ValueError):
        logger.warning(f"Invalid nominee_id during vote casting by user {current_user.username}: {raw_nominee_id}")
        return jsonify({"message": "Valid Nominee ID is required."}), 400

    # 2) Load nominee
    nominee = Nominee.query.get(nominee_id)
    if not nominee:
        logger.warning(f"Vote cast failed by user {current_user.username}: Nominee {nominee_id} not found")
        return jsonify({"message": "Nominee not found."}), 404

    # 3) Check voting-active setting
    voting_active_setting = AwardSetting.query.filter_by(key='voting_active').first()
    if not voting_active_setting or voting_active_setting.value.lower() != 'true':
        logger.info(f"Vote attempt by user {current_user.username} failed: Voting is not active.")
        return jsonify({"message": "Voting is currently not active."}), 403

    # 4) Enforce voting window
    start_cfg = AwardSetting.query.filter_by(key='voting_start_time').first()
    end_cfg = AwardSetting.query.filter_by(key='voting_end_time').first()
    now = datetime.datetime.utcnow()
    if start_cfg and end_cfg:
        try:
            start_time = datetime.datetime.fromisoformat(start_cfg.value)
            end_time = datetime.datetime.fromisoformat(end_cfg.value)
            if not (start_time <= now <= end_time):
                logger.info(f"Voting attempted outside window: now={now}, window={start_time}–{end_time}")
                return jsonify({"message": "Voting is outside the allowed time period."}), 403
        except ValueError:
            logger.error(
                "Invalid date format in voting_start_time or voting_end_time settings. Proceeding without time check.",
                exc_info=True)
            pass

    # 5) Determine free vs paid vote eligibility
    existing_free_vote_in_category = Vote.query.filter_by(
        user_id=current_user.id,
        category_id=nominee.category_id,
        is_paid_vote=False
    ).first()

    is_paid = False
    if existing_free_vote_in_category:
        # user already used free vote in this category
        if current_user.vote_balance > 0:
            current_user.vote_balance -= 1
            is_paid = True
            logger.info(f"User {current_user.id} using paid vote for category {nominee.category_id}.")
        else:
            logger.info(f"User {current_user.id} has no votes left for paid voting.")
            return jsonify({
                "message": "You have already used your free vote in this category and have no votes remaining."
            }), 403
    else:
        logger.info(f"User {current_user.id} casting free vote in category {nominee.category_id}.")

    # 6) Prepare new Vote record
    new_vote = Vote(
        user_id=current_user.id,
        nominee_id=nominee.id,
        category_id=nominee.category_id,
        is_paid_vote=is_paid
    )
    nominee.vote_count += 1

    # 7) Commit & respond
    try:
        db.session.add(new_vote)
        db.session.commit()
        vote_type = "paid vote" if is_paid else "free vote"
        logger.info(f"Vote recorded: user={current_user.id}, nominee={nominee.id}, type={vote_type}")
        return jsonify({
            "message": f"Vote cast successfully for {nominee.name}! ({vote_type})",
            "nominee_id": nominee.id,
            "new_nominee_vote_count": nominee.vote_count,
            "user_new_vote_balance": current_user.vote_balance,
            "category_id": nominee.category_id
        }), 200

    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error casting vote for user={current_user.id}, nominee={nominee.id}")
        return jsonify({"message": "Something went wrong casting your vote."}), 500

# --- End Vote Casting and Monetization Endpoints ---


# API to get live rankings for a specific category or all categories
@app.route('/api/rankings', methods=['GET'])
def get_live_rankings():
    """
    Retrieves live nominee rankings.
    Can be filtered by category_id.
    Controlled by 'show_live_rankings' setting.
    Query parameter: ?category_id=<int>
    """
    show_rankings_setting = AwardSetting.query.filter_by(key='show_live_rankings').first()
    if not show_rankings_setting or show_rankings_setting.value.lower() != 'true':
        logger.info("Attempt to retrieve live rankings failed: Rankings are not public.")
        return jsonify({"message": "Live rankings are currently not public."}), 403

    category_id = request.args.get('category_id', type=int)

    rankings_query = db.session.query(Nominee.id, Nominee.name, Nominee.vote_count, Nominee.category_id,
                                      Category.name.label('category_name')) \
        .join(Category)

    if category_id:
        category_exists = Category.query.get(category_id)
        if not category_exists:
            logger.warning(f"Attempt to retrieve rankings for non-existent category with ID: {category_id}")
            return jsonify({"message": "Category not found"}), 404
        rankings_query = rankings_query.filter(Nominee.category_id == category_id)

    rankings_query = rankings_query.order_by(Nominee.vote_count.desc())

    raw_rankings = rankings_query.all()

    output = []
    total_votes_in_category = 0
    if category_id:
        total_votes_in_category = db.session.query(db.func.sum(Nominee.vote_count)).filter_by(
            category_id=category_id).scalar() or 0
    else:
        # Sum all nominee votes if no specific category filter
        total_votes_in_app = db.session.query(db.func.sum(Nominee.vote_count)).scalar() or 0

    for rank, nominee_data in enumerate(raw_rankings):
        nominee_id, name, vote_count, cat_id, category_name = nominee_data

        # Calculate percentage only if we have a specific category and total votes are > 0
        percentage = None
        if category_id and total_votes_in_category > 0:
            percentage = (vote_count / total_votes_in_category * 100)

        output.append({
            'rank': rank + 1,
            'id': nominee_id,
            'name': name,
            'category_id': cat_id,
            'category_name': category_name,
            'vote_count': vote_count,
            'percentage': round(percentage, 2) if percentage is not None else None
        })
    logger.info(f"Live rankings retrieved (filtered by category_id: {category_id or 'None'}).")
    return jsonify({"rankings": output}), 200


# API for Admin to manage AwardSettings
@app.route('/api/admin/settings', methods=['GET'])
@admin_required
def get_award_settings(**kwargs):
    """
    Retrieves all award show settings. Admin only.
    """
    settings = AwardSetting.query.all()
    output = []
    for setting in settings:
        output.append({
            'id': setting.id,
            'key': setting.key,
            'value': setting.value,
            'description': setting.description
        })
    logger.info("Admin retrieved award settings.")
    return jsonify({"settings": output}), 200


@app.route('/api/admin/settings', methods=['PUT'])
@admin_required
def update_award_setting(**kwargs):
    """
    Updates a specific award show setting by its key. Admin only.
    Expects JSON input with 'key' and 'value'.
    """
    if not request.is_json:
        return jsonify({"message": "Request must be JSON"}), 400

    data = request.get_json()
    key = data.get('key')
    value = data.get('value')

    # Input validation for settings update
    if not key or not isinstance(key, str) or not (1 <= len(key) <= 100):
        logger.warning(f"Invalid setting key during update: {key}")
        return jsonify({"message": "Setting key is required and must be 1-100 characters long."}), 400
    if value is None or not isinstance(value, str) or len(value) > 255:
        # Value can be an empty string, but must be a string and within length
        logger.warning(f"Invalid setting value during update for key '{key}': {value}")
        return jsonify({"message": "Setting value is required and must be a string up to 255 characters."}), 400

    setting = AwardSetting.query.filter_by(key=key).first()
    if not setting:
        logger.warning(f"Attempt to update non-existent setting with key: {key}")
        return jsonify({"message": f"Setting with key '{key}' not found"}), 404

    setting.value = value  # Value is already string validated

    try:
        db.session.commit()
        logger.info(f"Setting '{key}' updated successfully to '{value}'.")
        return jsonify({
            "message": f"Setting '{key}' updated successfully!",
            "setting": {
                'id': setting.id,
                'key': setting.key,
                'value': setting.value,
                'description': setting.description
            }
        }), 200
    except Exception as e:
        db.session.rollback()
        logger.exception(f"Error updating setting with key '{key}'.")
        return jsonify({"message": "Something went wrong updating setting"}), 500


# --- End API Routes ---


if __name__ == '__main__':
    # Figure out which port to listen on (default to 5000 if PORT isn’t set)
    port = int(os.environ.get('PORT', 5000))

    # Log where we’re binding
    logger.info(f"Starting Flask application via Waitress server on port {port}…")

    # Serve with Waitress on 0.0.0.0:<port>
    serve(app, host='0.0.0.0', port=port)

    # If you ever want to run the Flask dev server instead, you could do:
    # app.run(debug=True, port=port)


