from flask import jsonify, request, Blueprint
from auth.utils import hash_password, generate_token, check_password
from storage import tasks, users


auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    if username in users:
        return jsonify({"message": "user already exists"}), 400
    
    if not username or not password:
        return jsonify({"message": "username and password required"}), 409

    hashed_pw = hash_password(password)
    users[username] = hashed_pw
    
    return jsonify({"message": f"user {username} created successfully!"}), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    """if not auth or not auth.get("username") or not auth.get("password"):
        return jsonify({"error": "credentials needed"}), 400
    if auth["username"] != user["username"] or auth["password"] != user["password"]:
        return jsonify({"error": "invalid credentials"}), 401"""
    
    username = data.get("username")
    password = data.get("password")
        
    
    hashed_pw = users.get(username)
    
    if not hashed_pw:
        return jsonify({"message": "user not found"}), 401
    
    if isinstance(hashed_pw, str):
        hashed_pw = hashed_pw.encode('utf-8')

    if not check_password(password, hashed_pw):
        return jsonify({"message": "wrong password"}), 401


    token = generate_token(username)
    return jsonify({"token": token})