# 📝 Task Manager API
A simple Flask-based REST API for managing tasks with JWT authentication.
Users can register, log in, and perform CRUD operations on their own tasks.

## 🚀 Features
- 🔐 User Authentication (Register & Login)

- 🔑 JWT Token Security

- 🗂 Task Management

    - Create a task

    - Get all tasks for the logged-in user

    - View a single task

    - Update a task

    - Delete a task

## 🛠 Tech Stack
- **Flask** – API framework

- **JWT** – Authentication

- **bcrypt** – Password hashing

- **Python** – Core programming language

## 📦 Installation

1. Clone the repo

`git clone <repo-url>`

`cd <repo-folder>`

2. Create a virtual environment

`python -m venv venv`

`source venv/bin/activate   # Mac/Linux`

`venv\Scripts\activate      # Windows`

3. Install dependencies

`pip install -r requirements.txt`

4. Set up environment variables

Create a .env file:

`SECRET_KEY=your_secret_key`

5. Run the app

`python app.py`

## 🔑 Authentication Flow

- **Register** → /auth/register

- **Login** → /auth/login → Returns JWT token

- **Access Task Endpoints** → Include token in request headers:
    
    `Authorization: Bearer <your_token>`

## 📚 API Endpoints

### Auth

**Method**	    **Endpoint**	    **Description**

POST	        `/auth/register`	Create a new account

POST	        `/auth/login`	    Log in & get token

### Tasks (Require JWT Token)

**Method**	    **Endpoint**	    **Description**

GET	            /tasks	            Get all tasks

POST	        /tasks	            Create a task

GET	            /tasks/<task_id>	Get single task

PUT	            /tasks/<task_id>	Update a task

DELETE	        /tasks/<task_id>	Delete a task

## 🧪 Example Request

### Create Task

`curl -X POST http://127.0.0.1:5000/tasks \`

`-H "Authorization: Bearer <your_token>" \`

`-H "Content-Type: application/json" \`

`-d '{"title": "Buy groceries", "description": "Milk, Eggs, Bread"}'`


