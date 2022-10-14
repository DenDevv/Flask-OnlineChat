from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import Length, DataRequired


class SignUpForm(FlaskForm):
    login = StringField(
        label=None,
        validators=[DataRequired(), Length(max=256)],
        render_kw={"placeholder": "Login"}
    )

    name = StringField(
        label=None,
        validators=[DataRequired(), Length(max=256)],
        render_kw={"placeholder": "Name"}
    )

    password = PasswordField(
        label=None,
        validators=[DataRequired(), Length(max=256)],
        render_kw={"placeholder": "Password"}
    )

    sign_up = SubmitField(
        label="Sign Up"
    )


class SignInForm(FlaskForm):
    login = StringField(
        label=None,
        validators=[DataRequired(), Length(max=256)],
        render_kw={"placeholder": "Login"}
    )

    password = PasswordField(
        label=None,
        validators=[DataRequired(), Length(max=256)],
        render_kw={"placeholder": "Password"}
    )

    remember = BooleanField(
        label='remain me'
    )

    sign_in = SubmitField(
        label="Sign In"
    )


class EditProfileForm(FlaskForm):
    name = StringField(
        label='New Name: ',
        validators=[Length(max=256)],
        render_kw={"placeholder": "New name"}
    )

    pic = FileField(
        label='Profile picture',
        validators=[FileAllowed(['png', 'jpg'])]
    )

    submit = SubmitField(
        label="Update"
    )


class ChatForm(FlaskForm):
    message = StringField(
        validators=[DataRequired(), Length(max=256)],
        render_kw={"placeholder": "Your message"}
    )

    send = SubmitField(
        label="Send"
    )