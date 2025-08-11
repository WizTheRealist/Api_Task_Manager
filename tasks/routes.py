from flask import Blueprint, request, jsonify
from auth.utils import token_required
import uuid
from storage import tasks, users

#define blueprint for task
tasks_bp = Blueprint('tasks', __name__)

#function to get all the tasks linked to a specific user
@tasks_bp.route('/tasks', methods=['GET'])
@token_required
def get_tasks(current_user):
    user_task = [task for task in tasks if task['user'] == current_user]
    return jsonify(user_task), 200


@tasks_bp.route('/tasks', methods=['POST'])
@token_required
def create_tasks(current_user):
    data = request.get_json()         #get user request in json format and store it in the variable "data"
    
    new_task = {
        "id": str(uuid.uuid4()),
        "title": data.get('title', 'Untitled Task'), #if the there is no title, fall back on default
        "description": data.get('description', ''),   #if there is no desc, fall back on default
        "user": current_user
    }

    tasks.append(new_task)
    return jsonify(new_task), 201

@tasks_bp.route('/tasks/<task_id>', methods=['GET'])
@token_required
def get_task(current_user, task_id):
    task = next((task for task in tasks if task['id'] == task_id and task['user'] == current_user), None)
    if not task:
        return jsonify({"message": "Task not found or access denied"}), 404
    return jsonify(task), 200
        

@tasks_bp.route('/tasks/<task_id>', methods=['PUT'])
@token_required
def update_tasks(current_user, task_id):
    
    task = next((task for task in tasks if task['id'] == task_id and task['user'] == current_user), None)
    if not task:
        return jsonify({"message": "task not found or access denied"}), 404
    
    data = request.get_json()
    task['title'] = data.get('title', task['title'])
    task['description'] = data.get('description', task['description'])
    
    return jsonify(task), 200


@tasks_bp.route('/tasks/<task_id>', methods=['DELETE'])
@token_required
def del_tasks(current_user, task_id):
    global tasks

    task = next((task for task in tasks if task['id'] == task_id and task['user'] == current_user), None)
    if not task:
        return jsonify({"message": "task not found or access denied"}), 404
    
    tasks = [t for t in tasks if not(t['id'] == task_id and t['user'] == current_user)]
    return jsonify({"message": "task deleled successfully"}), 200
