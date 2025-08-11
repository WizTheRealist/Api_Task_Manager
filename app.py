from flask import Flask
from auth.routes import auth_bp
from tasks.routes import tasks_bp
from config import Config

app = Flask(__name__)
app.config.from_object(Config)

app.register_blueprint(auth_bp, url_prefix='/auth')
app.register_blueprint(tasks_bp, url_prefix='/tasks')

@app.route('/')
def home():
    return "Task Manager Api is running"

if __name__ == '__main__':
    app.run(debug=True)