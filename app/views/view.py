import os
import rsa
import pickle

from datetime import datetime

from flask import Blueprint, render_template, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user

from app import db, images
from app.models import User, Role, Chat
from app.forms import SignUpForm, SignInForm, EditProfileForm, ChatForm


app_blueprint = Blueprint("app", __name__)


def generate_keys():
    pubkey, privkey = rsa.newkeys(512)

    key_dict = {
        'public' : pubkey.save_pkcs1(),
        'private' : privkey.save_pkcs1()
    }

    with open('app/static/keys/private.txt', 'wb') as file:
        pickle.dump(key_dict, file)


def encrypt_message(message):
    with open('app/static/keys/private.txt', 'rb') as file:
        data_file = pickle.load(file)
        public_key = rsa.PublicKey.load_pkcs1(data_file['public'])
        crypto_message = rsa.encrypt(message.encode("utf-8"), public_key)
    
    return crypto_message


def decrypt_message(message):
    with open('app/static/keys/private.txt', 'rb') as file:
        data_file = pickle.load(file)
        private_key = rsa.PrivateKey.load_pkcs1(data_file['private'])
        decrypt_message = rsa.decrypt(message, private_key).decode("utf-8")
    
    return decrypt_message


if not os.path.exists('app/static/keys/private.txt'):
    generate_keys()


@app_blueprint.route('/', methods=['GET'])
def home():
    return render_template("home.html")


@app_blueprint.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    userid = User.query.filter_by(id=current_user.id).first()
    name = current_user.name
    regtime = current_user.regtime
    image_file = url_for('static', filename=f'images/profile_pics/{userid.image_file}')

    if not os.path.exists(f"app/{image_file}"):
        userid.image_file = "default.png"
        image_file = url_for('static', filename=f'images/profile_pics/default.png')
    
    return render_template('profile.html', name=name, image_file=image_file, regtime=regtime, userid=userid)

    
@app_blueprint.route("/profile/update_profile", methods=["GET", "POST"])
def edit_profile():
    form = EditProfileForm()
    userid = User.query.filter_by(id=current_user.id).first()
    chat_record = Chat.query.filter_by(user_id=current_user.id).first()
    name = current_user.name
    regtime = current_user.regtime
    image_file = url_for('static', filename=f'images/profile_pics/{userid.image_file}')

    if not os.path.exists(f"app/{image_file}"):
        userid.image_file = "default.png"
        image_file = url_for('static', filename=f'images/profile_pics/default.png')

    if form.validate_on_submit():
        try:
            file_full_name = str(form.pic.data).split()[1].replace("'", "")
            ext = file_full_name.split(".")[1]

            if userid.image_file == "default.png":
                images.save(storage=form.pic.data, name=f"{userid.id}.{ext}")
            else:
                if os.remove(f"{userid.id}.{ext}"):
                    images.save(storage=form.pic.data, name=f"{userid.id}.{ext}")
            
            userid.image_file = f"{userid.id}.{ext}"
            db.session.commit()
            
        except:
            pass

        if form.name.data != None and len(form.name.data) != 0:
            if form.name.data != userid.name:
                userid.name = form.name.data
                db.session.commit()

                chat_record.username = form.name.data
                db.session.commit()
                return redirect(url_for('app.profile'))

            flash("This name is already taken!", "error")

        return redirect(url_for('app.profile'))

    return render_template("edit_profile.html", name=name, image_file=image_file, regtime=regtime, userid=userid, form=form)


@app_blueprint.route("/profile/delete", methods=["GET", "POST"])
def delete_profile():
    user = User.query.filter_by(id=current_user.id).first()
    user_role = Role.query.filter_by(id=current_user.id).first()

    if user and user_role:
        db.session.delete(user)
        db.session.commit()

        db.session.delete(user_role)
        db.session.commit()
    
    else:
        return redirect(url_for("app.home"))
    
    return redirect(url_for("app.home"))


@app_blueprint.route("/signup", methods=['GET', "POST"])
def signup():
    form = SignUpForm()

    if form.validate_on_submit():
        login = form.login.data
        name = form.name.data
        password = form.password.data
        regtime = datetime.strftime(datetime.now(), "%d/%m/%Y %H:%M:%S")

        user = User.query.filter_by(login=login).first()
        user_name = User.query.filter_by(name=name).first()

        if not user and not user_name and len(password) > 8:
            new_user = User(login=login,
                            name=name,
                            password=generate_password_hash(password, method='sha256'),
                            regtime=regtime
                            )

            simple_user_role = Role(name='user')

            new_user.roles = [simple_user_role,]

            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('app.signin'))

        flash('The fields are filled in incorrectly', 'error')

    return render_template("signup.html", form=form)


@app_blueprint.route("/signin", methods=['GET', "POST"])
def signin():
    form = SignInForm()

    if form.validate_on_submit():
        login = form.login.data
        password = form.password.data
        remember = form.remember.data

        user = User.query.filter_by(login=login).first()

        if user and check_password_hash(user.password, password):
            login_user(user, remember=remember)
            return redirect(request.args.get("next") or url_for('app.profile'))
        
        flash("Password or login entered incorrectly!", "error")

    return render_template("signin.html", form=form)


@app_blueprint.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('app.home'))


@app_blueprint.route("/chat", methods=["GET", "POST"])
@login_required
def chat():
    form = ChatForm()
    data = Chat.query.order_by(Chat.id.asc()).all()
    profile = User.query.filter_by(id=current_user.id).first()
    date = datetime.strftime(datetime.now(), "%d-%B %H:%M")

    if form.validate_on_submit():
        if Chat.query.filter_by(id=Chat.id).count() == 50:
            db.session.query(Chat).delete()
            name = profile.name
            message = form.message.data

            new_message = Chat(message=encrypt_message(message), username=name, user_id=profile.id, date=date, user_pic=profile.image_file)
            db.session.add(new_message)
            db.session.commit()
            return redirect(url_for('app.chat'))

        name = profile.name
        message = form.message.data

        new_message = Chat(message=encrypt_message(message), username=name, user_id=profile.id, date=date, user_pic=profile.image_file)
        db.session.add(new_message)
        db.session.commit()
        return redirect(url_for('app.chat'))
    
    return render_template("chat.html", form=form, data=data, profile=profile)


@app_blueprint.route("/check_profile/<id>", methods=["GET", "POST"])
@login_required
def check_profile(id):
    profile = User.query.filter_by(id=id).first()
    image_file = url_for('static', filename=f'images/profile_pics/{profile.image_file}')
    return render_template("check_profile.html", profile=profile, image_file=image_file)
