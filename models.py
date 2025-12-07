import os
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, text

db = SQLAlchemy()


class Role(db.Model):
    __tablename__ = 'roles'
    role_id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(50), nullable=False, unique=True)


class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

    full_name = db.Column(db.String(100))
    email = db.Column(db.String(100))
    phone = db.Column(db.String(45))
    gender = db.Column(db.String(10))  
    created_at = db.Column(
        db.DateTime,
        server_default=db.text("CURRENT_TIMESTAMP")
    )
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'), nullable=False)
    is_active = db.Column(db.Integer, default=1)
    force_password_change = db.Column(db.Integer, default=0)
    role = db.relationship('Role', backref=db.backref('users', lazy=True))

class Student(db.Model):
    __tablename__ = 'students'
    student_id = db.Column(db.Integer, primary_key=True)
    class_id = db.Column(db.Integer)  # FK to classes.class_id (not modeled here)
    users_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('student_profile', uselist=False))


class Teacher(db.Model):
    __tablename__ = 'teachers'
    teacher_id = db.Column(db.Integer, primary_key=True)
    subject_id = db.Column(db.Integer)  # FK to subjects.subject_id (not modeled here)
    users_user_id = db.Column(db.Integer, db.ForeignKey('users.user_id'), nullable=False)
    user = db.relationship('User', backref=db.backref('teacher_profile', uselist=False))


class Class(db.Model):
    __tablename__ = 'classes'
    class_id = db.Column(db.Integer, primary_key=True)
    class_name = db.Column(db.String(50), nullable=False)
    grade_level = db.Column(db.String(50), nullable=False)
    academic_year = db.Column(db.String(20), nullable=False)
    max_students = db.Column(db.Integer)
    is_active = db.Column(db.Integer, default=1)


class Subject(db.Model):
    __tablename__ = 'subjects'
    subject_id = db.Column(db.Integer, primary_key=True)
    subject_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    is_active = db.Column(db.Integer, default=1)


def init_app(app):
    # Build DB URI from env, fallback to mysql settings in db.py
    db_user = os.environ.get('DB_USER', 'root')
    db_pass = os.environ.get('DB_PASSWORD', 'qebfix-fiqgy4-kabGim')
    db_host = os.environ.get('DB_HOST', 'localhost')
    db_name = os.environ.get('DB_NAME', 'final_testing_lms_db1')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', f'mysql+mysqlconnector://{db_user}:{db_pass}@{db_host}/{db_name}'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)



