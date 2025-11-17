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
    role_id = db.Column(db.Integer, db.ForeignKey('roles.role_id'), nullable=False)
    is_active = db.Column(db.Integer, default=1)
    phone = db.Column(db.String(45))
    # Added for temp password workflow; created by ensure_schema if missing in DB
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


# TODO: Add Test/Exam Results models for the report functionality
# Example structure for future implementation:
#
# class Test(db.Model):
#     __tablename__ = 'tests'
#     test_id = db.Column(db.Integer, primary_key=True)
#     test_name = db.Column(db.String(100), nullable=False)
#     subject_id = db.Column(db.Integer, db.ForeignKey('subjects.subject_id'))
#     class_id = db.Column(db.Integer, db.ForeignKey('classes.class_id'))
#     test_date = db.Column(db.Date)
#     total_marks = db.Column(db.Integer)
#     duration_minutes = db.Column(db.Integer)
#     term = db.Column(db.String(20))  # 'Term 1', 'Term 2', 'Midterm', 'Final'
#     is_active = db.Column(db.Integer, default=1)
#
# class TestResult(db.Model):
#     __tablename__ = 'test_results'
#     result_id = db.Column(db.Integer, primary_key=True)
#     test_id = db.Column(db.Integer, db.ForeignKey('tests.test_id'), nullable=False)
#     student_id = db.Column(db.Integer, db.ForeignKey('students.student_id'), nullable=False)
#     marks_obtained = db.Column(db.Integer)
#     percentage = db.Column(db.Float)
#     grade = db.Column(db.String(2))  # A, B, C, D, F
#     remarks = db.Column(db.Text)
#     submitted_at = db.Column(db.DateTime)
#     graded_at = db.Column(db.DateTime)
#     graded_by = db.Column(db.Integer, db.ForeignKey('teachers.teacher_id'))


def init_app(app):
    # Build DB URI from env, fallback to mysql settings in db.py
    db_user = os.environ.get('DB_USER', 'root')
    db_pass = os.environ.get('DB_PASSWORD', 'qebfix-fiqgy4-kabGim')
    db_host = os.environ.get('DB_HOST', 'localhost')
    db_name = os.environ.get('DB_NAME', 'final_testing_lms_db')
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get(
        'DATABASE_URL', f'mysql+mysqlconnector://{db_user}:{db_pass}@{db_host}/{db_name}'
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    db.init_app(app)


def ensure_schema(app):
    # Ensure columns needed by new features exist in existing DB
    with app.app_context():
        inspector = inspect(db.engine)
        cols = [c['name'] for c in inspector.get_columns('users')]
        if 'force_password_change' not in cols:
            # Add column safely
            with db.engine.connect() as conn:
                conn.execute(text('ALTER TABLE users ADD COLUMN force_password_change TINYINT DEFAULT 0'))
        # Ensure basic roles exist
        try:
            if Role.query.count() == 0:
                db.session.add_all([
                    Role(role_id=1, role_name='Admin'),
                    Role(role_id=2, role_name='Teacher'),
                    Role(role_id=3, role_name='Student'),
                ])
                db.session.commit()
        except Exception:
            db.session.rollback()
