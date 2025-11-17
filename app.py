from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file, jsonify
from db import connect_db
import re
import os
import io
import csv
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
from models import init_app as init_models, ensure_schema, db, User, Role, Student, Teacher, Class, Subject
from sqlalchemy import func

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")

# Initialize SQLAlchemy models and ensure required schema bits exist
init_models(app)
ensure_schema(app)


def validate_username(username):
    if not username:
        return "Username is required."
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9_]{2,20}$", username):
        return "Username must start with a letter and be 3–20 characters."
    return ""


def validate_password(password):
    if not password:
        return "Password is required."
    if len(password) < 6:
        return "Password must be at least 6 characters."
    return ""


def is_logged_in():
    return "user" in session


def _get_cred_list():
    return session.setdefault("credential_list", [])


def _add_credential(username, temp_password, full_name="", email=""):
    creds = _get_cred_list()
    creds.append({
        "username": username, 
        "password": temp_password,
        "full_name": full_name,
        "email": email
    })
    session["credential_list"] = creds
    session.modified = True


def _generate_username(base: str) -> str:
    base = re.sub(r"[^a-zA-Z0-9]", "", base).lower()[:12] or "user"
    candidate = base
    n = 1
    with app.app_context():
        while User.query.filter(db.func.lower(User.username) == candidate).first():
            n += 1
            candidate = f"{base}{n}"
    return candidate


def _generate_password(length: int = 10) -> str:
    import secrets, string
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()"
    pw = ''.join(secrets.choice(alphabet) for _ in range(length))
    # Ensure complexity
    if not any(c.islower() for c in pw):
        pw = 'a' + pw[1:]
    if not any(c.isupper() for c in pw):
        pw = 'A' + pw[1:]
    if not any(c.isdigit() for c in pw):
        pw = '1' + pw[1:]
    return pw


@app.route("/", methods=["GET", "POST"])
def login():
    errors = {"username": "", "password": ""}
    username = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        errors["username"] = validate_username(username)
        errors["password"] = validate_password(password)

        if not errors["username"] and not errors["password"]:
            with app.app_context():
                user = User.query.filter(db.func.lower(User.username) == username.lower()).first()
                if user and check_password_hash(user.password, password):
                    if user.is_active == 0:
                        errors["password"] = "Account is inactive."
                    else:
                        session["user"] = user.username
                        session["role_id"] = user.role_id
                        session["user_id"] = user.user_id
                        if getattr(user, 'force_password_change', 0):
                            return redirect(url_for("change_password"))
                        if user.role_id == 1:
                            return redirect(url_for("admin_dashboard"))
                        elif user.role_id == 2:
                            return redirect(url_for("teacher_dashboard"))
                        else:
                            return redirect(url_for("student_dashboard"))
                else:
                    errors["password"] = "Invalid username or password."

    return render_template("login.html", username=username, errors=errors)


@app.route("/signup", methods=["GET", "POST"])
def signup():
    errors = {"username": "", "password": ""}

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        errors["username"] = validate_username(username)
        errors["password"] = validate_password(password)

        if not errors["username"] and not errors["password"]:
            with app.app_context():
                if User.query.filter(User.username == username).first():
                    errors["username"] = "Username already taken."
                else:
                    hashed = generate_password_hash(password)
                    u = User(username=username, password=hashed, full_name="New User", email="email@example.com", role_id=3, is_active=1, force_password_change=0)
                    db.session.add(u)
                    db.session.commit()
                    flash("Account created successfully!", "success")
                    return redirect(url_for("login"))

    return render_template("signup.html", errors=errors)


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        with app.app_context():
            user = User.query.filter(User.username == username).first()
            message = "Password reset link sent!" if user else "User not found."

    return render_template("forgot_password.html", message=message)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/home")
def home():
    if not is_logged_in():
        return redirect(url_for("login"))
    return render_template("home.html", username='session["user"]')


@app.route("/admin/dashboard")
def admin_dashboard():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))

    return render_template(
        "admin/admin_dashboard.html",
        total_students=120,
        total_teachers=15,
        total_classes=18,
        total_subjects=26,
        total_reports=42
    )

@app.route("/admin/grade")
def admin_grade():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))
    return render_template("admin/grade.html")

#region Vireak
@app.route("/admin/report")
def admin_report():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))
    
    # Fetch real data from database
    with app.app_context():
        # Get filter parameters
        grade_filter = request.args.get('grade', '')
        class_filter = request.args.get('class', '')
        subject_filter = request.args.get('subject', '')
        year_filter = request.args.get('year', '2024-2025')
        term_filter = request.args.get('term', '')
        
        # Count totals
        total_students = Student.query.count()
        total_teachers = Teacher.query.count()
        total_classes = Class.query.filter_by(is_active=1).count()
        total_subjects = Subject.query.filter_by(is_active=1).count()
        
        # Get all classes for filters
        classes = Class.query.filter_by(is_active=1).order_by(Class.grade_level, Class.class_name).all()
        
        # Get all subjects for filters
        subjects = Subject.query.filter_by(is_active=1).order_by(Subject.subject_name).all()
        
        # Get students with their class information
        students_query = (
            db.session.query(Student, User, Class)
            .join(User, Student.users_user_id == User.user_id)
            .outerjoin(Class, Student.class_id == Class.class_id)
            .filter(User.is_active == 1)
        )
        
        # Apply filters if provided
        if grade_filter:
            students_query = students_query.filter(Class.grade_level == grade_filter)
        if class_filter:
            students_query = students_query.filter(Class.class_name == class_filter)
        
        students_data = students_query.all()
        
        # Calculate statistics (using sample data for now as we don't have test results table yet)
        # These will be replaced when you add the test/exam results table
        pass_rate = 92.3  # Placeholder
        average_score = 78.5  # Placeholder
        top_performers = int(total_students * 0.48) if total_students > 0 else 0  # ~48% placeholder
        need_support = int(total_students * 0.09) if total_students > 0 else 0  # ~9% placeholder
        
        # Sample data for display (will be replaced with real test data)
        sample_results = []
        for idx, (student, user, class_obj) in enumerate(students_data[:12]):  # Show first 12
            sample_results.append({
                'student_id': f"#STU{student.student_id:03d}",
                'name': user.full_name or user.username,
                'class_name': class_obj.class_name if class_obj else 'N/A',
                'subject': 'Mathematics',  # Placeholder
                'test_date': '2025-11-10',  # Placeholder
                'score': 75 + (idx * 3) % 25,  # Placeholder
                'grade': 'B',  # Placeholder
                'status': 'Good',  # Placeholder
                'remarks': 'Consistent performance'  # Placeholder
            })
        
    return render_template(
        "admin/report.html",
        total_students=total_students,
        total_teachers=total_teachers,
        total_classes=total_classes,
        total_subjects=total_subjects,
        pass_rate=pass_rate,
        average_score=average_score,
        top_performers=top_performers,
        need_support=need_support,
        classes=classes,
        subjects=subjects,
        sample_results=sample_results,
        filters={
            'grade': grade_filter,
            'class': class_filter,
            'subject': subject_filter,
            'year': year_filter,
            'term': term_filter
        }
    )
@app.route("/admin/add_class", methods=["GET", "POST"])
def admin_add_class():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "create":
            class_name = request.form.get("class_name", "").strip()
            grade_level = request.form.get("grade_level", "").strip()
            academic_year = request.form.get("academic_year", "").strip()
            max_students = request.form.get("max_students", "").strip()

            if not class_name or not grade_level or not academic_year:
                flash("Please fill out class name, grade level and academic year.", "danger")
            else:
                try:
                    max_students_val = int(max_students) if max_students else None
                except ValueError:
                    flash("Max students must be a number.", "danger")
                    max_students_val = None

                if not (max_students and max_students_val is None):
                    new_class = Class(
                        class_name=class_name,
                        grade_level=grade_level,
                        academic_year=academic_year,
                        max_students=max_students_val,
                        is_active=1,
                    )
                    db.session.add(new_class)
                    db.session.commit()
                    flash("Class added successfully.", "success")

        elif action == "update":
            class_id = request.form.get("class_id")
            class_name = request.form.get("class_name", "").strip()
            grade_level = request.form.get("grade_level", "").strip()
            academic_year = request.form.get("academic_year", "").strip()
            max_students = request.form.get("max_students", "").strip()

            if not class_id:
                flash("Invalid class ID.", "danger")
            elif not class_name or not grade_level or not academic_year:
                flash("Please fill out class name, grade level and academic year.", "danger")
            else:
                try:
                    max_students_val = int(max_students) if max_students else None
                except ValueError:
                    flash("Max students must be a number.", "danger")
                    max_students_val = None

                if not (max_students and max_students_val is None):
                    c = Class.query.get(class_id)
                    if not c:
                        flash("Invalid class ID.", "danger")
                    else:
                        c.class_name = class_name
                        c.grade_level = grade_level
                        c.academic_year = academic_year
                        c.max_students = max_students_val
                        db.session.commit()
                        flash("Class updated successfully.", "success")

        elif action == "deactivate":
            class_id = request.form.get("class_id")
            if class_id:
                c = Class.query.get(class_id)
                if c:
                    c.is_active = 0
                    db.session.commit()
                    flash("Class deactivated.", "warning")
                else:
                    flash("Invalid class ID.", "danger")
            else:
                flash("Invalid class ID.", "danger")

        elif action == "activate":
            class_id = request.form.get("class_id")
            if class_id:
                c = Class.query.get(class_id)
                if c:
                    c.is_active = 1
                    db.session.commit()
                    flash("Class activated.", "success")
                else:
                    flash("Invalid class ID.", "danger")
            else:
                flash("Invalid class ID.", "danger")

        # After POST, redirect to avoid form resubmission
        return redirect(url_for("admin_add_class"))

    # GET: fetch all classes
    classes = Class.query.order_by(Class.class_id.desc()).all()

    # If editing, load the specific record
    edit_id = request.args.get("edit_id")
    edit_class = Class.query.get(edit_id) if edit_id else None

    return render_template("admin/add_class.html", classes=classes, edit_class=edit_class)


@app.route("/admin/add_subject", methods=["GET", "POST"])
def admin_add_subject():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)

    try:
        if request.method == "POST":
            action = request.form.get("action")

            if action == "create":
                subject_name = request.form.get("subject_name", "").strip()
                description = request.form.get("description", "").strip()

                if not subject_name:
                    flash("Subject name is required.", "danger")
                else:
                    cursor.execute(
                        """
                        INSERT INTO subjects (subject_name, description, is_active)
                        VALUES (%s, %s, 1)
                        """,
                        (subject_name, description if description else None)
                    )
                    conn.commit()
                    flash("Subject added successfully.", "success")

            elif action == "update":
                subject_id = request.form.get("subject_id")
                subject_name = request.form.get("subject_name", "").strip()
                description = request.form.get("description", "").strip()

                if not subject_id:
                    flash("Invalid subject ID.", "danger")
                elif not subject_name:
                    flash("Subject name is required.", "danger")
                else:
                    cursor.execute(
                        """
                        UPDATE subjects
                        SET subject_name=%s, description=%s
                        WHERE subject_id=%s
                        """,
                        (subject_name, description if description else None, subject_id)
                    )
                    conn.commit()
                    flash("Subject updated successfully.", "success")

            elif action == "deactivate":
                subject_id = request.form.get("subject_id")
                if subject_id:
                    cursor.execute("UPDATE subjects SET is_active=0 WHERE subject_id=%s", (subject_id,))
                    conn.commit()
                    flash("Subject deactivated.", "warning")
                else:
                    flash("Invalid subject ID.", "danger")

            elif action == "activate":
                subject_id = request.form.get("subject_id")
                if subject_id:
                    cursor.execute("UPDATE subjects SET is_active=1 WHERE subject_id=%s", (subject_id,))
                    conn.commit()
                    flash("Subject activated.", "success")
                else:
                    flash("Invalid subject ID.", "danger")

            return redirect(url_for("admin_add_subject"))

        # GET: fetch all subjects
        cursor.execute(
            "SELECT subject_id, subject_name, description, is_active FROM subjects ORDER BY subject_id DESC"
        )
        subjects = cursor.fetchall()

        # If editing, load the specific record
        edit_id = request.args.get("edit_id")
        edit_subject = None
        if edit_id:
            cursor.execute(
                "SELECT subject_id, subject_name, description, is_active FROM subjects WHERE subject_id=%s",
                (edit_id,)
            )
            edit_subject = cursor.fetchone()

        return render_template("admin/add_subject.html", subjects=subjects, edit_subject=edit_subject)

    finally:
        cursor.close()
        conn.close()


@app.route("/admin/users")
def admin_users():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))
    # Provide lists for template
    with app.app_context():
        students = (
            Student.query
            .join(User, Student.users_user_id == User.user_id)
            .outerjoin(Class, Student.class_id == Class.class_id)
            .add_columns(
                Student.student_id, 
                Class.class_name,
                User.user_id, 
                User.username, 
                User.full_name, 
                User.email, 
                User.phone, 
                User.is_active,
                Student.class_id
            )
            .all()
        )
        teachers = (
            Teacher.query
            .join(User, Teacher.users_user_id == User.user_id)
            .outerjoin(Subject, Teacher.subject_id == Subject.subject_id)
            .add_columns(
                Teacher.teacher_id, 
                Subject.subject_name,
                User.user_id, 
                User.username, 
                User.full_name, 
                User.email, 
                User.phone, 
                User.is_active,
                Teacher.subject_id
            )
            .all()
        )
    # Fetch available classes (active and not full) and active subjects for the Add User modal using ORM
    # Available classes: active and below capacity (or unlimited when max_students is NULL)
    student_count = func.count(Student.student_id)
    available_classes = (
        db.session.query(Class)
        .outerjoin(Student, Student.class_id == Class.class_id)
        .filter(Class.is_active == 1)
        .group_by(
            Class.class_id,
            Class.class_name,
            Class.grade_level,
            Class.academic_year,
            Class.max_students,
            Class.is_active,
        )
        .having((Class.max_students == None) | (student_count < Class.max_students))
        .order_by(Class.grade_level, Class.class_name)
        .all()
    )

    active_subjects = Subject.query.filter_by(is_active=1).order_by(Subject.subject_name).all()
    creds_available = len(_get_cred_list()) > 0
    return render_template(
        "admin/user.html",
        students=students,
        teachers=teachers,
        creds_available=creds_available,
        available_classes=available_classes,
        active_subjects=active_subjects,
    )


@app.route("/admin/users/create", methods=["POST"])
def admin_create_user_related():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))
    entity = request.form.get("entity")  # 'student' or 'teacher'
    full_name = request.form.get("full_name", "").strip() or "New User"
    email = request.form.get("email", "").strip() or None
    phone = request.form.get("phone", "").strip() or None
    class_id = request.form.get("class_id")
    subject_id = request.form.get("subject_id")
    role_id = 3 if entity == 'student' else 2
    username = _generate_username(full_name.split()[0] if full_name else entity)
    temp_pw = _generate_password()
    hashed = generate_password_hash(temp_pw)
    with app.app_context():
        u = User(username=username, password=hashed, full_name=full_name, email=email, role_id=role_id, is_active=1, phone=phone, force_password_change=1)
        db.session.add(u)
        db.session.flush()
        if entity == 'student':
            s = Student(class_id=int(class_id) if class_id else None, users_user_id=u.user_id)
            db.session.add(s)
        else:
            t = Teacher(subject_id=int(subject_id) if subject_id else None, users_user_id=u.user_id)
            db.session.add(t)
        db.session.commit()
    _add_credential(username, temp_pw, full_name, email or "")
    flash(f"{entity.title()} and user created. Credentials added to one-time list.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/reset_password/<int:user_id>", methods=["POST"]) 
def admin_reset_password(user_id):
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))
    with app.app_context():
        u = User.query.get_or_404(user_id)
        temp_pw = _generate_password()
        u.password = generate_password_hash(temp_pw)
        u.force_password_change = 1
        db.session.commit()
        _add_credential(u.username, temp_pw, u.full_name or "", u.email or "")
    flash("Temporary password generated. Download it now; it won't be shown again.", "warning")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/toggle_status/<int:user_id>", methods=["POST"])
def admin_toggle_user_status(user_id):
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))
    with app.app_context():
        u = User.query.get_or_404(user_id)
        u.is_active = 0 if u.is_active == 1 else 1
        db.session.commit()
        status = "activated" if u.is_active == 1 else "deactivated"
        flash(f"User {u.username} has been {status}.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/edit/<int:user_id>", methods=["POST"])
def admin_edit_user(user_id):
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))
    with app.app_context():
        u = User.query.get_or_404(user_id)
        u.full_name = request.form.get("full_name", "").strip() or u.full_name
        u.email = request.form.get("email", "").strip() or u.email
        u.phone = request.form.get("phone", "").strip() or u.phone
        
        # Update student or teacher specific info
        if u.role_id == 3 and u.student_profile:
            class_id = request.form.get("class_id", "").strip()
            if class_id:
                u.student_profile.class_id = int(class_id) if class_id else None
        elif u.role_id == 2 and u.teacher_profile:
            subject_id = request.form.get("subject_id", "").strip()
            if subject_id:
                u.teacher_profile.subject_id = int(subject_id) if subject_id else None
        
        db.session.commit()
        flash(f"User {u.username} has been updated.", "success")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/credentials/download")
def admin_download_credentials():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))
    creds = _get_cred_list()
    if not creds:
        flash("No credentials to download.", "info")
        return redirect(url_for("admin_users"))
    # Determine desired format (default to CSV)
    fmt = (request.args.get('format') or 'csv').lower()

    # Build file content
    if fmt == 'txt':
        output = io.StringIO()
        print("Full Name, Email, Username, Temporary Password", file=output)
        for item in creds:
            full_name = item.get('full_name', '')
            email = item.get('email', '')
            print(f"{full_name}, {email}, {item['username']}, {item['password']}", file=output)
        data = io.BytesIO(output.getvalue().encode('utf-8'))
        output.close()
        filename = f"credentials_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        mimetype = 'text/plain'
    else:
        # CSV as the default
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Full Name", "Email", "Username", "Temporary Password"])
        for item in creds:
            full_name = item.get('full_name', '')
            email = item.get('email', '')
            writer.writerow([full_name, email, item['username'], item['password']])
        data = io.BytesIO(output.getvalue().encode('utf-8'))
        output.close()
        filename = f"credentials_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        mimetype = 'text/csv'

    # Clear immediately to ensure one-time visibility
    session["credential_list"] = []
    
    # Seek to beginning of BytesIO object before sending
    data.seek(0)
    return send_file(data, as_attachment=True, download_name=filename, mimetype=mimetype)


@app.route("/change_password", methods=["GET", "POST"])
def change_password():
    if not is_logged_in():
        return redirect(url_for("login"))
    error = ""
    if request.method == "POST":
        new_pw = request.form.get("new_password", "").strip()
        confirm_pw = request.form.get("confirm_password", "").strip()
        if len(new_pw) < 6:
            error = "Password must be at least 6 characters."
        elif new_pw != confirm_pw:
            error = "Passwords do not match."
        else:
            with app.app_context():
                u = User.query.get(session.get("user_id"))
                if u:
                    u.password = generate_password_hash(new_pw)
                    u.force_password_change = 0
                    db.session.commit()
                    flash("Password changed successfully.", "success")
                    return redirect(url_for("login"))
    return render_template("change_password.html", error=error)


@app.route('/admin/users/import', methods=['POST'])
def admin_import_users():
    if not is_logged_in() or session.get('role_id') != 1:
        return redirect(url_for('login'))
    file = request.files.get('file')
    entity = request.form.get('entity')  # student or teacher
    if not file or not entity:
        flash('Please select a CSV file and entity type.', 'danger')
        return redirect(url_for('admin_users'))
    filename = file.filename.lower()
    if not filename.endswith('.csv'):
        flash('Only CSV files are supported in this build.', 'warning')
        return redirect(url_for('admin_users'))
    stream = io.TextIOWrapper(file.stream, encoding='utf-8')
    reader = csv.DictReader(stream)
    created = 0
    with app.app_context():
        for row in reader:
            full_name = (row.get('full_name') or '').strip() or (row.get('name') or 'New User')
            email = (row.get('email') or '').strip() or None
            phone = (row.get('phone') or '').strip() or None
            class_id = (row.get('class_id') or '').strip()
            subject_id = (row.get('subject_id') or '').strip()
            role_id = 3 if entity == 'student' else 2
            username = _generate_username(full_name.split()[0] if full_name else entity)
            temp_pw = _generate_password()
            hashed = generate_password_hash(temp_pw)
            u = User(username=username, password=hashed, full_name=full_name, email=email, role_id=role_id, is_active=1, phone=phone, force_password_change=1)
            db.session.add(u)
            db.session.flush()
            if entity == 'student':
                s = Student(class_id=int(class_id) if class_id else None, users_user_id=u.user_id)
                db.session.add(s)
            else:
                t = Teacher(subject_id=int(subject_id) if subject_id else None, users_user_id=u.user_id)
                db.session.add(t)
            _add_credential(username, temp_pw, full_name, email or "")
            created += 1
        db.session.commit()
    flash(f"Imported {created} {entity}s and generated credentials.", 'success')
    return redirect(url_for('admin_users'))


#endregion



# Minimal Roles CRUD JSON endpoints
@app.route('/admin/roles', methods=['GET'])
def roles_list():
    if not is_logged_in() or session.get('role_id') != 1:
        return redirect(url_for('login'))
    with app.app_context():
        roles = [{"role_id": r.role_id, "role_name": r.role_name} for r in Role.query.order_by(Role.role_id).all()]
    return jsonify(roles)


@app.route('/admin/roles', methods=['POST'])
def roles_create():
    if not is_logged_in() or session.get('role_id') != 1:
        return redirect(url_for('login'))
    name = request.form.get('role_name')
    if not name:
        return jsonify({"error": "role_name required"}), 400
    with app.app_context():
        r = Role(role_name=name)
        db.session.add(r)
        db.session.commit()
    return jsonify({"message": "created", "role_id": r.role_id})


@app.route('/admin/roles/<int:role_id>', methods=['PUT', 'PATCH'])
def roles_update(role_id):
    if not is_logged_in() or session.get('role_id') != 1:
        return redirect(url_for('login'))
    name = request.form.get('role_name')
    with app.app_context():
        r = Role.query.get_or_404(role_id)
        if name:
            r.role_name = name
            db.session.commit()
    return jsonify({"message": "updated"})


@app.route('/admin/roles/<int:role_id>', methods=['DELETE'])
def roles_delete(role_id):
    if not is_logged_in() or session.get('role_id') != 1:
        return redirect(url_for('login'))
    with app.app_context():
        r = Role.query.get_or_404(role_id)
        db.session.delete(r)
        db.session.commit()
    return jsonify({"message": "deleted"})



@app.route("/teacher")
def teacher_dashboard():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    return render_template("teacher/teacher_dashboard.html")


@app.route("/teacher/students")
def teacher_students():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    return render_template("teacher/students.html")


@app.route("/teacher/report")
def teacher_report():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    return render_template("teacher/report.html")


@app.route("/teacher/test_creation")
def teacher_test_creation():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    return render_template("teacher/test_creation.html")


@app.route("/teacher/grade")
def teacher_grade():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    return render_template("teacher/grade.html")


@app.route("/student")
def student_dashboard():
    if not is_logged_in() or session.get("role_id") != 3:
        return redirect(url_for("login"))
    return render_template("student/student_dashboard.html")


@app.route("/student/quiz")
def student_quiz():
    if not is_logged_in() or session.get("role_id") != 3:
        return redirect(url_for("login"))
    return render_template("student/quiz.html")


@app.route("/student/report")
def student_report():
    if not is_logged_in() or session.get("role_id") != 3:
        return redirect(url_for("login"))
    return render_template("student/report.html")

@app.route("/manage_grades")
def manage_grades():
    return render_template("admin/grade.html")

@app.route("/assign_test")
def assign_test():
    return render_template("admin/assign_test.html")

@app.route("/results/<grade>/<class_name>")
def class_results(grade, class_name):
    # later you can load results from DB here
    return render_template("admin/results_page.html", grade=grade, class_name=class_name)


if __name__ == "__main__":
    app.run(debug=True)
