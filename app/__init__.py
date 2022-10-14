from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_uploads import configure_uploads, IMAGES, UploadSet


# instantiate extensions
db = SQLAlchemy()
login_manager = LoginManager()
images = UploadSet('images', IMAGES)


# creating app
def create_app():

    from app.views import app_blueprint, decrypt_message

    from app.models import (
        User,
        Role,
        Chat
    )

    # Instantiate app.
    app = Flask(__name__)
    app.secret_key = '=RtT2@nEF9=DXEULem5MMR%5+@*#zxpX'
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///./database/data.db"
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config['UPLOADED_IMAGES_DEST'] = 'app/static/images/profile_pics'
    app.config['WTF_CSRF_ENABLED'] = False

    app.jinja_env.globals.update(decrypt_message=decrypt_message)

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