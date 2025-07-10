# tests/test_api_auth.py
from app import db, User, app  # Import app here for app_context
import json


# Test user registration API
def test_register_user(client):
    response = client.post('/api/register', json={
        'username': 'newuser',
        'email': 'new@example.com',
        'password': 'password123'
    })
    assert response.status_code == 201
    assert 'User registered successfully!' in response.json['message']

    with app.app_context():
        user = User.query.filter_by(username='newuser').first()
        assert user is not None
        assert user.email == 'new@example.com'
        assert user.check_password('password123')


# Test registration with existing username
def test_register_existing_username(client):
    client.post('/api/register', json={
        'username': 'existinguser',
        'email': 'exist1@example.com',
        'password': 'password123'
    })
    response = client.post('/api/register', json={
        'username': 'existinguser',
        'email': 'exist2@example.com',
        'password': 'password123'
    })
    assert response.status_code == 409
    assert 'Username already exists' in response.json['message']


# Test user login API
def test_login_user(client):
    # First, register a user
    client.post('/api/register', json={
        'username': 'loginuser',
        'email': 'login@example.com',
        'password': 'loginpass'
    })

    # Then, attempt to log in
    response = client.post('/api/login', json={
        'username': 'loginuser',
        'password': 'loginpass'
    })
    assert response.status_code == 200
    assert 'token' in response.json
    assert isinstance(response.json['token'], str)


# Test login with invalid credentials
def test_login_invalid_credentials(client):
    response = client.post('/api/login', json={
        'username': 'nonexistent',
        'password': 'wrongpassword'
    })
    assert response.status_code == 401
    assert 'Invalid credentials' in response.json['message']


# Test protected route access
def test_protected_route_access(client):
    # Register and log in a user to get a token
    client.post('/api/register', json={
        'username': 'protecteduser',
        'email': 'protected@example.com',
        'password': 'protectedpass'
    })
    login_response = client.post('/api/login', json={
        'username': 'protecteduser',
        'password': 'protectedpass'
    })
    token = login_response.json['token']

    # Access the protected route with the token
    response = client.get('/api/protected', headers={'x-access-token': token})
    assert response.status_code == 200
    assert 'You accessed a protected route!' in response.json['message']
    assert response.json['user_username'] == 'protecteduser'


# Test protected route access without token
def test_protected_route_no_token(client):
    response = client.get('/api/protected')
    assert response.status_code == 401
    assert 'Token is missing!' in response.json['message']


# Test protected route access with invalid token
def test_protected_route_invalid_token(client):
    response = client.get('/api/protected', headers={'x-access-token': 'invalid.token.here'})
    assert response.status_code == 401
    assert 'Token is invalid!' in response.json['message']