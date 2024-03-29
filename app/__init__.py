from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_uploads import configure_uploads, IMAGES, UploadSet
from flask_socketio import SocketIO


# instantiate extensions
db = SQLAlchemy()
login_manager = LoginManager()
images = UploadSet('images', IMAGES)

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")


# creating app
def create_app():
    from app.views import app_blueprint

    from app.models import (
        User,
        Role,
        Chat
    )

    # Instantiate app.
    app.secret_key = ''
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./data.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config['UPLOADED_IMAGES_DEST'] = 'app/static/images/profile_pics'
    app.config['WTF_CSRF_ENABLED'] = False

    configure_uploads(app, images)

    # Set up extensions.
    db.init_app(app)

    with app.app_context():
        db.create_all()

    login_manager.init_app(app)

    # Register blueprints.
    app.register_blueprint(app_blueprint)

    # Set up flask login.
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    login_manager.login_view = 'app.signin'
    login_manager.login_message = 'You must be signed in!'
    login_manager.login_message_category = 'error'

    return app
