from flask import Flask,render_template,request,redirect,url_for,jsonify,session
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from flask_login import LoginManager,UserMixin, login_user, logout_user, current_user,login_required
import jwt
from bson.objectid import ObjectId
from functools import wraps
import re
from datetime import datetime  # For adding a timestamp to the estimation data
import secrets  # For generating a secure secret key (if needed)
import numpy as np
from bson import ObjectId
import datetime


client=MongoClient("mongodb://localhost:27017/") # database connection
db=client["effort_estimation_tool"] # database name
users_collection=db["users"]  # collection name for user
task_collection = db['task_details']
estimation_collection = db['estimations'] 
historical_data_collection = db['historical_data']
counters_collection = db['counters']


# historical_data = [
#     {
#         "task_id": 1,
#         "task_name": "Develop Login Module",
#         "complexity": "Medium",
#         "size": "Large",
#         "task_type": "Development",
#         "estimated_effort_hours": 40,
#         "confidence_level": "Medium",
#         "estimated_range_hours": "35-45"
#     },
#     {
#         "task_id": 2,
#         "task_name": "Implement Database Migration",
#         "complexity": "High",
#         "size": "Medium",
#         "task_type": "Database",
#         "estimated_effort_hours": 60,
#         "confidence_level": "High",
#         "estimated_range_hours": "55-60"
#     },
#     {
#         "task_id": 3,
#         "task_name": "Design User Interface",
#         "complexity": "Low",
#         "size": "Small",
#         "task_type": "Design",
#         "estimated_effort_hours": 20,
#         "confidence_level": "Low",
#         "estimated_range_hours": "18-22"
#     },
#     {
#         "task_id": 4,
#         "task_name": "Test Payment Gateway",
#         "complexity": "High",
#         "size": "Medium",
#         "task_type": "Testing",
#         "estimated_effort_hours": 30,
#         "confidence_level": "Medium",
#         "estimated_range_hours": "25-35"
#     },
#     {
#         "task_id": 5,
#         "task_name": "Perform Regression Testing",
#         "complexity": "High",
#         "size": "Large",
#         "task_type": "Testing",
#         "estimated_effort_hours": 50,
#         "confidence_level": "High",
#         "estimated_range_hours": "45-55"
#     },
#     {
#         "task_id": 6,
#         "task_name": "Optimize Queries for Performance",
#         "complexity": "Medium",
#         "size": "Large",
#         "task_type": "Development",
#         "estimated_effort_hours": 45,
#         "confidence_level": "High",
#         "estimated_range_hours": "40-50"
#     },
#     {
#         "task_id": 7,
#         "task_name": "Follow Material Design Guidelines",
#         "complexity": "Low",
#         "size": "Medium",
#         "task_type": "Design",
#         "estimated_effort_hours": 25,
#         "confidence_level": "Low",
#         "estimated_range_hours": "20-30"
#     },
#     {
#         "task_id": 8,
#         "task_name": "Refactor Legacy Code",
#         "complexity": "High",
#         "size": "Large",
#         "task_type": "Development",
#         "estimated_effort_hours": 70,
#         "confidence_level": "Medium",
#         "estimated_range_hours": "65-75"
#     },
#     {
#         "task_id": 9,
#         "task_name": "Write API Documentation",
#         "complexity": "Low",
#         "size": "Small",
#         "task_type": "Development",
#         "estimated_effort_hours": 15,
#         "confidence_level": "Low",
#         "estimated_range_hours": "12-18"
#     },
#     {
#         "task_id": 10,
#         "task_name": "Test Performance of Application",
#         "complexity": "High",
#         "size": "Large",
#         "task_type": "Testing",
#         "estimated_effort_hours": 55,
#         "confidence_level": "High",
#         "estimated_range_hours": "50-60"
#     }
# ]

# # Insert historical data into MongoDB
# historical_data_collection.insert_many(historical_data)
# # historical_data_collection.delete_many({})
# print("Historical data inserted successfully.")

app = Flask(__name__)
app.secret_key = secrets.token_bytes(32)  # Generate a secret key

# Configure Flask-Login
#the login manager contains the code that lets your application and Flask-Login work together, 
#such as how to load a user from an ID, where to send users when they need to log in, and the like.
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login if unauthorized



# Initialize the counters collection
if counters_collection.find_one({"_id": "task_id"}) is None:
    counters_collection.insert_one({"_id": "task_id", "task_id": 0})

class User(UserMixin):
    def __init__(self,id,username,password_hash):
        self.id = id
        self.username=username
        self.password_hash=password_hash

    def verify_password(self,password):
        return check_password_hash(self.password_hash,password)

    @staticmethod
    def find_by_username(username):
        user_data = users_collection.find_one({"username": username})
        if user_data:
            return User(id=user_data["_id"],username=user_data["username"], password_hash=user_data["password_hash"])
        return None

    

@login_manager.user_loader
def load_user(user_id):
  '''
  You will need to provide a user_loader callback. 
  This callback is used to reload the user object from the user ID stored in the session. 
  It should take the str ID of a user, and return the corresponding user object.
  '''
  try:
    if isinstance(user_id, str):
      user_id = ObjectId(user_id)  # Convert string ObjectID to ObjectId
  except (TypeError, ValueError):
    print("Invalid user ID format.")
    return None

  user = users_collection.find_one({"_id": user_id})
  return User(user["_id"], user["username"], user["password_hash"]) if user else None


# @app.route('/get_username',methods=['GET'])
# def get_username():
#     # Check if the username is stored in the session
#     if 'username' in session:
#         username = session['username']
#         return jsonify({'username': username})
#     else:
#         return jsonify({'username': None})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/success')
def success():
    return render_template('success.html')


# Function to get user ID from session
def get_user_id():
    return session.get('user_id')


# Create a function to get the next task ID
def get_next_task_id():
    last_task = historical_data_collection.find_one(sort=[("task_id", -1)])
    if last_task:
        return last_task['task_id'] + 1
    else:
        return 1

def serialize_doc(doc):
    """
    Convert MongoDB document to a JSON serializable format.
    """
    serialized_doc = {}
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            serialized_doc[key] = str(value)
        else:
            serialized_doc[key] = value
    return serialized_doc

@app.route('/register', methods=['GET','POST'])
def register():
    error_message = None
    already_registered_message = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Check if the username is already registered
        if users_collection.find_one({"username": username}):
            already_registered_message = "Username already exists. Please choose a different one."
        else:
            # Validate username and password
            if not is_valid_username(username):
                error_message = 'Invalid username'
            elif not is_strong_password(password):
                error_message = 'Weak password'
            else:
                # Hash the password
                hashed_password = generate_password_hash(password)

                # Create a new user
                new_user = {"username": username, "password_hash": hashed_password}

                # Insert the new user into the database
                users_collection.insert_one(new_user)


                # Log in the newly registered user
                login_user(User(new_user["_id"], username, hashed_password)) # Create a User object

                # Redirect to a success page or login page
                return redirect(url_for('success'))

    return render_template('register.html', error_message=error_message, already_registered_message=already_registered_message)



def is_valid_username(username):
    # Username must be at least 6 characters long
    if len(username) < 6:
        return False

    # Username must contain at least one character, one number, and one special character
    if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$%^&+=])[A-Za-z\d@#$%^&+=]+$', username):
        return False

    return True

def is_strong_password(password):
    # Password must be at least 8 characters long
    if len(password) < 8:
        return False

    # Password must contain at least one character, one number, and one special character
    if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)(?=.*[@#$%^&+=])[A-Za-z\d@#$%^&+=]+$', password):
        return False

    return True

def generate_jwt(user_data, secret_key=None):
    """Generates a JSON Web Token (JWT) using the HS256 algorithm.

    Args:
        user_data (dict): A dictionary containing user information to be included
                          in the payload of the JWT. The 'user_id' key is recommended.
        secret_key (str, optional): The secret key used for signing the JWT.
                                    If not provided, a secure random key will be
                                    generated using secrets.token_bytes().

    Returns:
        str: The encoded JWT string.

    Raises:
        ValueError: If 'user_id' is not present in the user_data dictionary.
    """

    if "user_id" not in user_data:
        raise ValueError("Missing required key 'user_id' in user_data dictionary")

    # Ensure a secret key is available
    if secret_key is None:
        secret_key = app.secret_key

    # Encode the JWT using HS256 algorithm
    payload = {
        "user_id": user_data["user_id"],
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expiration time
    }
    encoded_jwt = jwt.encode(payload, secret_key, algorithm='HS256')
    return encoded_jwt

# JWT required decorator
def jwt_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = request.cookies.get('jwt_token')
        if not token:
            return jsonify({"error": "Missing authorization header"}), 401

        try:
            decoded_data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = {"user_id": decoded_data["user_id"]}
            return f(current_user,*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid JWT token need to login again"}), 401

    return decorated_function


@app.route('/login', methods=['GET', 'POST'])
def login():
    error_message = None

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.find_by_username(username)
        if not user:
            error_message = 'Invalid username'
        elif not user.verify_password(password):
            error_message = 'Invalid password'
        else:
            token = generate_jwt({'user_id': username})
            session['username'] = username
            response = redirect(url_for('dashboard'))
            response.set_cookie('jwt_token', token, httponly=True, secure=True)
            return response

    return render_template('login.html', error_message=error_message)


@app.route('/dashboard')
@jwt_required
def dashboard(current_user):
    username = session.get('username')
    return render_template('dashboard.html', user_id=current_user['user_id'],username=username)



@app.route('/logout')
@login_required
def logout():
    session.pop('user_id', None)
    logout_user()
    return redirect(url_for('login'))





@app.route('/create_historical_data', methods=['GET', 'POST'])
@jwt_required
def create_historical_data(current_user):
    if request.method == 'POST':
        task_id = get_next_task_id()
        task_name = request.form['task_name']
        complexity = request.form['complexity']
        size = request.form['size']
        task_type = request.form['task_type']
        estimated_effort_hours = int(request.form['estimated_effort_hours'])
        confidence_level = request.form['confidence_level']
        estimated_range_hours = request.form['estimated_range_hours']

        new_data = {
            "task_id": task_id,
            "task_name": task_name,
            "complexity": complexity,
            "size": size,
            "task_type": task_type,
            "estimated_effort_hours": estimated_effort_hours,
            "confidence_level": confidence_level,
            "estimated_range_hours": estimated_range_hours
        }

        historical_data_collection.insert_one(new_data)
        return redirect(url_for('view_historical_data'))

    return render_template('create_historical_data.html')

@app.route('/view_historical_data')
@jwt_required
def view_historical_data(current_user):
    historical_data = list(historical_data_collection.find())
    return render_template('view_historical_data.html', historical_data=historical_data)

@app.route('/update_historical_data/<int:task_id>', methods=['POST'])
@jwt_required
def update_historical_data(task_id):
    # Extract updated data from the request
    updated_data = request.json

    # Update the record in the database
    result = historical_data_collection.update_one(
        {"task_id": task_id},
        {"$set": updated_data}
    )

    if result.modified_count > 0:
        message = "Record updated successfully"
    else:
        message = "No record updated"

    return jsonify({"message": message})

@app.route('/delete_historical_data/<int:task_id>', methods=['POST'])
def delete_historical_data(task_id):
    result = historical_data_collection.delete_one({"task_id": task_id})
    if result.deleted_count:
        return jsonify({"message": "Record deleted successfully"}), 200
    return jsonify({"message": "Record not found"}), 404

# Task Submission Page
@app.route('/submit_task', methods=['GET'])
@jwt_required
def show_submission_form(current_user):
    return render_template('submit_form.html')


# view all submitted task

@app.route('/task_list', methods=['GET'])
@jwt_required
def submitted_tasks(current_user):
    submitted_tasks =list(task_collection.find())
    return render_template('submitted_tasks.html', submitted_tasks=submitted_tasks)

# Submit Task
@app.route('/submit', methods=['POST','GET'])
@jwt_required
def submit_task(current_user):
    user_id = get_user_id()
    # if not user_id:
    #     return redirect(url_for('login'))

    task_name = request.form['taskName']
    complexity = request.form['complexity']
    size = request.form['size']
    task_type = request.form['taskType']
    additional_notes = request.form['additionalNotes']

    

    task_id = get_next_task_id()

    task_collection.insert_one({
        "task_id": task_id,
        "user_id": user_id,
        "task_name": task_name,
        "complexity": complexity,
        "size": size,
        "task_type": task_type,
        "additional_notes": additional_notes
    })

    return render_template('submit_success.html', task_name=task_name)

@app.route('/show_estimate', methods=['GET'])
@jwt_required
def show_estimation_form(current_user):
    return render_template('estimate_form.html')

@app.route('/estimation_list', methods=['GET'])
@jwt_required
def estimation_list(current_user):
    estimations = list(estimation_collection.find())
    return render_template('estimation_list.html', estimations=estimations)

# Calculate Estimation
@app.route('/estimate', methods=['POST'])
@jwt_required
def calculate_estimation(current_user):
    user_id = get_user_id()  # Get the current user ID
    task_name = request.form["task_name"]
    task = task_collection.find_one({"task_name": task_name})

    # Retrieve the task details for the current user
    if not task:
        return "Task not found"

    task = serialize_doc(task)

    similar_tasks = historical_data_collection.find({
        "complexity": task["complexity"],
        "size": task["size"],
        "task_type": task["task_type"]
    })

    efforts = [similar_task['estimated_effort_hours'] for similar_task in similar_tasks]

    if efforts:
        estimated_effort = np.mean(efforts)
        std_dev = np.std(efforts)
    else:
        estimated_effort = 0
        std_dev = 0

    # Determine confidence level based on task size
    if task["size"].lower() == "large":
        confidence_level = "High"
    elif task["size"].lower() == "medium":
        confidence_level = "Medium"
    else:
        confidence_level = "Low"

    if std_dev > 0:
        lower_bound = max(0, estimated_effort - std_dev)
        upper_bound = estimated_effort + std_dev
        estimated_range = f"{lower_bound:.2f}-{upper_bound:.2f}"
    else:
        # Handle the case where std_dev is 0, meaning no variation in data
        estimated_range = f"{estimated_effort:.2f}-{(estimated_effort + 10):.2f}" 

   # add historical data
    historical_data = {
        "task_id": task["task_id"],
        "task_name": task["task_name"],
        "complexity": task["complexity"],
        "size": task["size"],
        "task_type": task["task_type"],
        "estimated_effort_hours": estimated_effort,
        "confidence_level": confidence_level,
        "estimated_range_hours": estimated_range
    }
        
    

    historical_data_collection.insert_one(historical_data)
    historical_data= serialize_doc(historical_data)

    estimation_result = {
        "task_id": task["task_id"],
        "estimated_effort_hours": estimated_effort,
        "confidence_level": confidence_level,
        "estimated_range_hours": estimated_range
    }

    estimation_collection.insert_one(estimation_result)
    estimation_result = serialize_doc(estimation_result)
    return render_template('estimation_result.html', estimation_result=estimation_result)


if __name__ == '__main__':
    app.run(debug=True, port=5010)