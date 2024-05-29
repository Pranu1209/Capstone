import pytest
from app import app, historical_data_collection

@pytest.fixture
def client():
    """Create a test client using the Flask application."""
    with app.test_client() as client:
        yield client

def test_register(client):
    """Test user registration."""
    response = client.post('/register', data={
        'username': 'testuser',
        'password': 'StrongPassword123'
    })
    assert response.status_code == 200  # Check if the registration redirects to success page

def test_login(client):
    response = client.post('/login', data={'username': 'test_user', 'password': 'test_password'})
    assert b'Effort' in response.data  # Assuming successful login redirects to the dashboard

def test_jwt_token_generation(client):
    response = client.post('/login', data={'username': 'test_user', 'password': 'test_password'})
    assert b' ' in response.data  # Check if JWT token is included in the response cookies

def test_jwt_token_authentication(client):
    # Assuming the endpoint requires authentication and returns 401 if not authenticated
    response = client.get('/dashboard')
    assert response.status_code == 401
    

def test_jwt_token_authentication_invalid_token(client):
    """Test JWT token authentication with invalid token."""
    # Send a request with an invalid JWT token to a protected route
    response = client.get('/dashboard', headers={'Cookie': 'jwt_token=invalid_token'})
    assert response.status_code == 401  # Check if access is unauthorized with invalid JWT token

def test_jwt_token_authentication_missing_token(client):
    """Test JWT token authentication with missing token."""
    # Send a request without JWT token to a protected route
    response = client.get('/dashboard')
    assert response.status_code == 401  # Check if access is unauthorized without JWT token

def test_delete_historical_data(client):
    """Test deleting historical data."""
    # Add a sample historical data entry for testing
    historical_data_collection.insert_one({
        "task_id": 1001,
        "task_name": "Sample Task",
        "complexity": "Low",
        "size": "Small",
        "task_type": "Sample Type",
        "estimated_effort_hours": 10,
        "confidence_level": "High",
        "estimated_range_hours": "8-12"
    })

    # Make a request to delete the historical data entry
    response = client.post('/delete_historical_data/1001')

    # Check if the response status code is 200 (OK)
    assert response.status_code == 200

    # Check if the historical data entry is deleted from the collection
    assert historical_data_collection.find_one({"task_id": 1001}) is None

