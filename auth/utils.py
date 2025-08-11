import bcrypt, jwt
from config import Config
from datetime import timedelta, timezone, datetime
from functools import wraps
from flask import request, jsonify
from storage import tasks, users

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(password, hashed_pw):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_pw)

def generate_token(username):
    return jwt.encode(
        {"username": username,"exp": datetime.now(timezone.utc) + timedelta(hours=1)},
        Config.SECRET_KEY,
        algorithm="HS256"
    )

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
            return jsonify({"message": "Token is missing"}), 401
        
        try:
            data = jwt.decode(token, Config.SECRET_KEY, algorithms=["HS256"])
            current_user = data['username']
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token is expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid Token"}), 401
        
        return f(current_user, *args, **kwargs)
    return decorated