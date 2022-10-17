from flask_login import UserMixin

from app import db


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    regtime = db.Column(db.String(50), nullable=False)
    image_file = db.Column(db.String(100), nullable=False, default='default.png')
    roles = db.relationship('Role', secondary='user_roles')

    def has_roles(self, *args):
        return set(args).issubset({role.name for role in self.roles})
        
class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer(), primary_key=True)
    name = db.Column(db.String(50))


class UserRoles(db.Model):
    __tablename__ = 'user_roles'
    id = db.Column(db.Integer(), primary_key=True)
    user_id = db.Column(db.Integer(), db.ForeignKey('users.id', ondelete='CASCADE'))
    role_id = db.Column(db.Integer(), db.ForeignKey('roles.id', ondelete='CASCADE'))


class Chat(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer(), primary_key=True)
    message = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer(), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    user_pic = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(50), nullable=False)