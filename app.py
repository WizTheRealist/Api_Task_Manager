from flask import Flask, jsonify, request
from functools import wraps
import jwt, datetime, bcrypt, uuid
from datetime import timedelta, timezone, datetime

app = Flask(__name__)

users = {}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        
        token = None

        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            parts = auth_header.split()
            if len(parts) == 2 and parts[0] == 'Bearer':
                token = parts[1]
        
        if not token:
            return jsonify({"message": "token is missing"}), 401
        
        try:
            decoded = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = decoded["username"]
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "token has expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "token is invalid"}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated



@app.route('/')
def home():
    return "Task Manager Api is running"

tasks = []

SECRET_KEY = "mysecretflaskkey"


@app.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    user_task = [task for task in tasks if task['user'] == current_user]
    return jsonify(user_task), 200

@app.route('/tasks', methods=['POST'])
@token_required
def create_tasks(current_user):
    data = request.get_json()
    
    new_task = {
        "id": str(uuid.uuid4()),
        "title": data.get('title', 'Untitled Task'),
        "description": data.get('decription', ''),
        "user": current_user
    }

    tasks.append(new_task)
    return jsonify(new_task), 201

@app.route('/tasks/<task_id>', methods=['GET'])
@token_required
def get_task(current_user, task_id):
    task = next((task for task in tasks if task['id'] == task_id and task['user'] == current_user), None)
    if not task:
        return jsonify({"message": "Task not found or access denied"}), 404
    return jsonify(task), 200
        

@app.route('/tasks/<task_id>', methods=['PUT'])
@token_required
def update_tasks(current_user, task_id):
    
    task = next((task for task in tasks if task['id'] == task_id and task['user'] == current_user), None)
    if not task:
        return jsonify({"message": "task not found or access denied"}), 404
    
    data = request.get_json()
    task['title'] = data.get('title', task['title'])
    task['description'] = data.get('description', task['description'])
    
    return jsonify(task), 200


@app.route('/tasks/<task_id>', methods=['DELETE'])
@token_required
def del_tasks(current_user, task_id):
    global tasks

    task = next((task for task in tasks if task['id'] == task_id and task['user'] == current_user), None)
    if not task:
        return jsonify({"message": "task not found or access denied"}), 404
    
    tasks = [t for t in tasks if not(t['id'] == task_id and t['user'] == current_user)]
    return jsonify({"message": "task deleled successfully"}), 200


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in users:
        return jsonify({"message": "user already exists"}), 400
    
    if not username or not password:
        return jsonify({"message": "username and password required"}), 409

    hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    
    users[username] = hashed_pw.decode('utf-8')
    return jsonify({"message": f"user {username} created successfully!"}), 201


@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()

    """if not auth or not auth.get("username") or not auth.get("password"):
        return jsonify({"error": "credentials needed"}), 400
    if auth["username"] != user["username"] or auth["password"] != user["password"]:
        return jsonify({"error": "invalid credentials"}), 401"""
    
    username = auth.get("username")
    password = auth.get("password")
        
    
    hashed_pw = users.get(username)
    
    if not hashed_pw:
        return jsonify({"message": "user not found"}), 401
    
    if isinstance(hashed_pw, str):
        hashed_pw = hashed_pw.encode('utf-8')

    if not bcrypt.checkpw(password.encode('utf-8'), hashed_pw):
        return jsonify({"message": "wrong password"}), 401


    token = jwt.encode({
        "username": username,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=30)
    }, SECRET_KEY, algorithm="HS256")

    return jsonify({"token": token})


if __name__ == '__main__':
    app.run(debug=True)