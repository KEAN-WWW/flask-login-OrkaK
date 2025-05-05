from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(128), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __init__(self, email, password):
        self.email = email
        self.password = self.set_password(password)

    def save(self):
        db.session.add(self)
        db.session.commit()

    def check_password(self, password):
        return check_password_hash(self.password, password)

    @staticmethod
    def set_password(password):
        return generate_password_hash(password)

    @classmethod
    def create(cls, email, password):
        user = cls(email=email, password=password)
        db.session.add(user)
        db.session.commit()
        return user

    @classmethod
    def find_user_by_email(cls, email):
        return cls.query.filter_by(email=email).first()
