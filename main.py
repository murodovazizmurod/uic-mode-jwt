from flask import Flask, jsonify, request, redirect, url_for
from flask_jwt_extended import create_access_token, jwt_required, JWTManager
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Mapped, mapped_column
from werkzeug.security import generate_password_hash, check_password_hash
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
import torch
from flask_swagger_ui import get_swaggerui_blueprint
from flask_cors import CORS
from flask_admin import Admin, AdminIndexView
from flask_admin.contrib.sqla import ModelView
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
import json

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

db = SQLAlchemy()
app.config["JWT_SECRET_KEY"] = "sagnsi@H$II$HQ#BHB!@I#B"
app.config["SECRET_KEY"] = "ASD^*^DAS&*D&SAD%AS"  # Secret key for Flask-Login
jwt = JWTManager(app)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///project.db"
db.init_app(app)

login_manager = LoginManager(app)
login_manager.login_view = 'admin_login'

pipe = pipeline("text-classification", model="blackhole33/sharq-model-uzb")

class User(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str]

class Review(db.Model):
    id: Mapped[int] = mapped_column(primary_key=True)
    text: Mapped[str]
    label: Mapped[str]

class AdminUser(db.Model, UserMixin):
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(unique=True)
    password: Mapped[str]

@login_manager.user_loader
def load_user(user_id):
    return AdminUser.query.get(int(user_id))

class MyModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin_login'))

class MyAdminIndexView(AdminIndexView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        return redirect(url_for('admin_login'))

admin = Admin(app, name='Admin Dashboard', template_mode='bootstrap4', index_view=MyAdminIndexView())
admin.add_view(MyModelView(User, db.session))
admin.add_view(MyModelView(Review, db.session))

tokenizer = AutoTokenizer.from_pretrained("blackhole33/sharq-model-uzb", from_pt=True)
model = AutoModelForSequenceClassification.from_pretrained("blackhole33/sharq-model-uzb")

def get_label(input_text):
    input = tokenizer(input_text, return_tensors="pt")
    model.eval()
    with torch.no_grad():
        outputs = model(**input)

    torch.set_printoptions(sci_mode=False)
    probas = torch.softmax(outputs.logits, dim=-1)
    predictions = torch.argmax(probas, dim=1)
    ans = predictions[0].item()

    if ans == 0:
        return 'Rejected (not based on experience)'
    elif ans == 1:
        return 'Accepted'
    elif ans == 2:
        return 'Rejected (rating mismatch)'
    else:
        return "Rejected (innappropriate content)"

@app.route("/login", methods=["POST"])
def login():
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    user = User.query.filter_by(username=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({"msg": "Bad username or password"}), 401

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route("/register", methods=["POST"])
def register():
    username = request.json.get("username", None)
    password = request.json.get("password", None)

    if not username or not password:
        return jsonify({"msg": "Username and password are required"}), 400

    user = User.query.filter_by(username=username).first()
    if user:
        return jsonify({"msg": "Username already exists"}), 409

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()

    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

@app.route("/review_check", methods=["POST"])
@jwt_required()
def review_check():
    text = request.json.get("text", None)
    if text:
        label = get_label(text)
        review = Review(text=text, label=label)
        db.session.add(review)
        db.session.commit()
    else:
        label = 'where is text?'
    return jsonify(data=label), 200

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = AdminUser.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("admin.index"))
        else:
            return "Invalid username or password", 401

    return '''
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Admin Login</title>
            <style>
                body {
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    height: 100vh;
                    background-color: #f7f7f7;
                    margin: 0;
                    font-family: Arial, sans-serif;
                }
                .login-container {
                    background-color: #ffffff;
                    padding: 20px 40px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
                }
                .login-container h2 {
                    margin-bottom: 20px;
                    font-size: 24px;
                    color: #333333;
                }
                .login-container input[type="text"], .login-container input[type="password"] {
                    width: 100%;
                    padding: 10px;
                    margin-bottom: 15px;
                    border: 1px solid #dddddd;
                    border-radius: 4px;
                    box-sizing: border-box;
                }
                .login-container input[type="submit"] {
                    width: 100%;
                    padding: 10px;
                    background-color: #4CAF50;
                    color: white;
                    border: none;
                    border-radius: 4px;
                    cursor: pointer;
                    font-size: 16px;
                }
                .login-container input[type="submit"]:hover {
                    background-color: #45a049;
                }
            </style>
        </head>
        <body>
            <div class="login-container">
                <h2>Admin Login</h2>
                <form method="post">
                    <input type="text" name="username" placeholder="Username" required>
                    <input type="password" name="password" placeholder="Password" required>
                    <input type="submit" value="Login">
                </form>
            </div>
        </body>
        </html>
    '''

@app.route("/admin/logout")
@login_required
def admin_logout():
    logout_user()
    return redirect(url_for("admin_login"))

SWAGGER_URL = '/swagger'
API_URL = '/swagger.json'
swaggerui_blueprint = get_swaggerui_blueprint(
    SWAGGER_URL,
    API_URL,
    config={
        'app_name': "Text Classification API"
    }
)
app.register_blueprint(swaggerui_blueprint, url_prefix=SWAGGER_URL)

@app.route("/swagger.json")
def swagger_json():
    with open('swagger.json', 'r') as f:
        return jsonify(json.load(f))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Create a default admin user
        if not AdminUser.query.filter_by(username="admin").first():
            hashed_password = generate_password_hash("uicpassword", method='pbkdf2:sha256')
            new_admin = AdminUser(username="admin", password=hashed_password)
            db.session.add(new_admin)
            db.session.commit()
    app.run(port=5000)
