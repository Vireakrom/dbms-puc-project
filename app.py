from flask import Flask, render_template, redirect, url_for, request, session, flash, send_file, jsonify
import re
import os
import io
import csv
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
from models import init_app as init_models, db, User, Role, Student, Teacher, Class, Subject
from sqlalchemy import func


app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecretkey")
app.permanent_session_lifetime = timedelta(days=30)

# Initialize SQLAlchemy models and ensure required schema bits exist
init_models(app)


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
        remember = request.form.get("remember") == "on"

        errors["username"] = validate_username(username)
        errors["password"] = validate_password(password)

        if not errors["username"] and not errors["password"]:
            with app.app_context():
                user = User.query.filter(db.func.lower(User.username) == username.lower()).first()
                if user and check_password_hash(user.password, password):
                    log_activity(user.user_id, "Logged in")
                    if user.is_active == 0:
                        errors["password"] = "Account is inactive."
                    else:
                        session.permanent = remember
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

    total_students = db.session.execute(
        db.text("SELECT COUNT(*) FROM students")
    ).scalar()

    total_teachers = db.session.execute(
        db.text("SELECT COUNT(*) FROM teachers")
    ).scalar()

    total_classes = db.session.execute(
        db.text("SELECT COUNT(*) FROM classes WHERE is_active = 1")
    ).scalar()

    total_subjects = db.session.execute(
        db.text("SELECT COUNT(*) FROM subjects WHERE is_active = 1")
    ).scalar()

    notifications = db.session.execute(db.text("""
        SELECT 
            al.log_id, 
            al.action, 
            al.timestamp,
            u.full_name AS user_name
        FROM activity_logs al
        LEFT JOIN users u ON u.user_id = al.user_id
        ORDER BY al.timestamp DESC
        LIMIT 5
    """)).fetchall()

   
    top_result = 60
    average_result = 30
    fail_result = 10
    grades = db.session.execute(db.text("""
        SELECT DISTINCT grade_level
        FROM classes
        ORDER BY grade_level
    """)).fetchall()

    teachers = db.session.execute(db.text("""
        SELECT user_id, full_name
        FROM users
        WHERE role_id = 2 AND is_active = 1
        ORDER BY full_name
    """)).fetchall()

    years = db.session.execute(db.text("""
        SELECT DISTINCT academic_year
        FROM classes
        ORDER BY academic_year DESC
    """)).fetchall()

    live_exams = db.session.execute(db.text("""
        SELECT 
            q.quiz_id,
            q.title,
            q.exam_type,
            q.percentage_weight,
            q.class_id,
            q.teacher_id,
            u.full_name AS teacher_name,
            s.subject_name,
            c.class_name,
            c.grade_level,
            q.start_time,
            q.end_time,
            q.is_active,

            -- Student count
            (SELECT COUNT(*) FROM students st WHERE st.class_id = q.class_id) AS total_students,

            -- Minutes remaining
            TIMESTAMPDIFF(MINUTE, NOW(), q.end_time) AS minutes_left,

            -- Determine exam status
            CASE
                WHEN NOW() < q.start_time THEN 'upcoming'
                WHEN NOW() BETWEEN q.start_time AND q.end_time THEN 'live'
                ELSE 'finished'
            END AS status

        FROM quizzes q
        JOIN subjects s ON q.subject_id = s.subject_id
        JOIN classes c ON q.class_id = c.class_id
        LEFT JOIN teachers t ON q.teacher_id = t.teacher_id
        LEFT JOIN users u ON t.users_user_id = u.user_id

        ORDER BY 
            CASE
                WHEN NOW() < q.start_time THEN 1          -- Upcoming first
                WHEN NOW() BETWEEN q.start_time AND q.end_time THEN 2  -- Live next
                ELSE 3                                    -- Finished last
            END,
            q.start_time ASC
    """)).fetchall()

    return render_template(
        "admin/admin_dashboard.html",

        total_students=total_students,
        total_teachers=total_teachers,
        total_classes=total_classes,
        total_subjects=total_subjects,

        notifications=notifications,

        top_result=top_result,
        average_result=average_result,
        fail_result=fail_result,

        grades=grades,
        teachers=teachers,
        years=years,

        live_exams=live_exams,

        active_page="dashboard"
    )


@app.route("/admin/get_subjects/<int:class_id>")
def get_subjects(class_id):
    rows = db.session.execute(db.text("""
        SELECT s.subject_id, s.subject_name
        FROM subjects_has_classes shc
        JOIN subjects s ON s.subject_id = shc.subject_id
        WHERE shc.class_id = :cid
        ORDER BY s.subject_name ASC
    """), {"cid": class_id}).fetchall()

    return jsonify([
        {"id": r.subject_id, "name": r.subject_name}
        for r in rows
    ])

@app.route("/admin/examination", methods=["GET"])
def examination_form():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))

    grades = db.session.execute(db.text("""
        SELECT DISTINCT grade_level
        FROM classes
        ORDER BY grade_level ASC
    """)).fetchall()

    return render_template("admin/examination.html", grades=grades)


@app.route("/admin/get_results")
def get_results():
    grade = request.args.get("grade")
    teacher_id = request.args.get("teacher_id")
    year = request.args.get("year")

    query = """
        SELECT g.total_marks
        FROM grades g
        JOIN students s ON g.student_id = s.student_id
        JOIN classes c ON s.class_id = c.class_id
        WHERE 1=1
    """

    params = {}

    if grade:
        query += " AND c.grade_level = :grade"
        params["grade"] = grade

    if teacher_id:
        query += " AND g.teacher_id = :teacher_id"
        params["teacher_id"] = teacher_id

    if year:
        query += " AND c.academic_year = :year"
        params["year"] = year

    rows = db.session.execute(db.text(query), params).fetchall()

    scores = [r.total_marks for r in rows]

    if not scores:
        return jsonify({
            "top": 0,
            "avg": 0,
            "fail": 0
        })

    top = sum(1 for s in scores if s >= 80)
    avg = sum(1 for s in scores if 60 <= s < 80)
    fail = sum(1 for s in scores if s < 60)

    return jsonify({
        "top": top,
        "avg": avg,
        "fail": fail
    })
@app.route("/admin/get_teachers_by_grade")
def get_teachers_by_grade():
    grade = request.args.get("grade", type=int)

    if not grade:
        return jsonify([])

    teacher_rows = db.session.execute(db.text("""
        SELECT DISTINCT 
            t.teacher_id,
            u.full_name
        FROM classes c
        JOIN classes_has_teachers cht 
            ON cht.classes_class_id = c.class_id
        JOIN teachers t 
            ON t.teacher_id = cht.teachers_teacher_id
        JOIN users u 
            ON u.user_id = t.users_user_id
        WHERE c.grade_level = :grade
          AND u.is_active = 1
    """), {"grade": grade}).fetchall()

    teachers = [
        {"teacher_id": row.teacher_id, "full_name": row.full_name}
        for row in teacher_rows
    ]

    return jsonify(teachers)

@app.route("/admin/grade")
def admin_grade():
    return redirect(url_for("admin_manage_grades"))

#region Vireak
@app.route("/admin/report/get-classes-by-grade")
def get_classes_by_grade():
    """API endpoint to fetch classes for a specific grade or all classes"""
    if not is_logged_in() or session.get("role_id") != 1:
        return jsonify({'error': 'Unauthorized'}), 403
    
    grade = request.args.get('grade', '').strip()
    
    with app.app_context():
        if grade:
            # Fetch classes for the selected grade
            classes = Class.query.filter_by(grade_level=grade, is_active=1).order_by(Class.class_name).all()
        else:
            # Fetch all classes
            classes = Class.query.filter_by(is_active=1).order_by(Class.grade_level, Class.class_name).all()
        
        return jsonify({
            'classes': [{'class_id': c.class_id, 'class_name': c.class_name, 'grade_level': c.grade_level} for c in classes]
        })


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
    
    from_dashboard = request.args.get("from_dashboard")
    active_page = "dashboard" if from_dashboard else "report"
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
        },
        active_page=active_page
    )

@app.route("/admin/add_class", methods=["GET", "POST"])
def admin_add_class():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))

    from_dashboard = request.args.get("from_dashboard")

    if request.method == "POST":
        action = request.form.get("action")
        class_id = request.form.get("class_id")

        # Helper: Convert max_students safely
        def safe_int(value):
            try:
                return int(value) if value else None
            except ValueError:
                return None

        # ---------- CREATE ----------
        if action == "create":
            class_name = request.form.get("class_name", "").strip()
            grade_level = request.form.get("grade_level", "").strip()
            academic_year = request.form.get("academic_year", "").strip()
            max_students_val = safe_int(request.form.get("max_students"))

            if not class_name or not grade_level or not academic_year:
                flash("Please fill out class name, grade level and academic year.", "danger")
            else:
                if max_students_val is None and request.form.get("max_students"):
                    flash("Max students must be a number.", "danger")
                else:
                    new_class = Class(
                        class_name=class_name,
                        grade_level=grade_level,
                        academic_year=academic_year,
                        max_students=max_students_val,
                        is_active=1
                    )
                    db.session.add(new_class)
                    db.session.commit()

                    log_activity(session["user_id"], f"Created class {class_name}")
                    flash("Class added successfully.", "success")

        # ---------- UPDATE ----------
        elif action == "update":
            class_obj = Class.query.get(class_id)
            if not class_obj:
                flash("Invalid class ID.", "danger")
            else:
                class_name = request.form.get("class_name", "").strip()
                grade_level = request.form.get("grade_level", "").strip()
                academic_year = request.form.get("academic_year", "").strip()
                max_students_val = safe_int(request.form.get("max_students"))

                if not class_name or not grade_level or not academic_year:
                    flash("Please fill out all fields.", "danger")
                elif max_students_val is None and request.form.get("max_students"):
                    flash("Max students must be numeric.", "danger")
                else:
                    class_obj.class_name = class_name
                    class_obj.grade_level = grade_level
                    class_obj.academic_year = academic_year
                    class_obj.max_students = max_students_val
                    db.session.commit()

                    log_activity(session["user_id"], f"Updated class ID {class_id}")
                    flash("Class updated successfully.", "success")

        # ---------- DEACTIVATE ----------
        elif action == "deactivate":
            class_obj = Class.query.get(class_id)
            if class_obj:
                class_obj.is_active = 0
                db.session.commit()
                log_activity(session["user_id"], f"Deactivated class {class_obj.class_name}")
                flash("Class deactivated.", "success")
            else:
                flash("Invalid class ID.", "danger")

        # ---------- ACTIVATE ----------
        elif action == "activate":
            class_obj = Class.query.get(class_id)
            if class_obj:
                class_obj.is_active = 1
                db.session.commit()
                log_activity(session["user_id"], f"Activated class ID {class_id}")
                flash("Class activated.", "success")
            else:
                flash("Invalid class ID.", "danger")

        return redirect(url_for("admin_add_class"))


    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)

    if per_page not in [10, 25, 50, 100]:
        per_page = 10

    classes_pagination = Class.query.order_by(Class.class_id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    edit_id = request.args.get("edit_id")
    edit_class = Class.query.get(edit_id) if edit_id else None

    def get_active_page(default_page):
        if request.args.get("from_dashboard"):
            return "dashboard"
        if request.args.get("from_grade"):
            return "grade"
        return default_page

    active_page = get_active_page("add_class")

    return render_template(
        "admin/add_class.html",
        classes_pagination=classes_pagination,
        edit_class=edit_class,
        active_page=active_page,
    )
@app.route("/admin/results/<int:class_id>")
def admin_results(class_id):

    # --- 1. Get class information ---
    class_data = db.session.execute(db.text("""
        SELECT class_name, grade_level, academic_year
        FROM classes
        WHERE class_id = :cid
    """), {"cid": class_id}).fetchone()

    if not class_data:
        return "Class not found", 404

    class_name = class_data.class_name
    grade = class_data.grade_level
    current_year = class_data.academic_year

    # --- 2. Fetch test results for this class ---
    results = db.session.execute(db.text("""
        SELECT 
            tr.result_id,
            tr.test_date,
            s.student_id,
            u.full_name AS student_name,

            tr.quiz_score,
            tr.assignment_score,
            tr.midterm_score,
            tr.final_score,
            tr.total_score,       -- UPDATED COLUMN NAME
            tr.grade,

            sub.subject_name,
            u2.full_name AS teacher_name
        FROM test_results tr
        JOIN students s ON s.student_id = tr.student_id
        JOIN users u ON u.user_id = s.users_user_id
        JOIN subjects sub ON sub.subject_id = tr.subject_id
        JOIN teachers t ON t.teacher_id = tr.teacher_id
        JOIN users u2 ON u2.user_id = t.users_user_id
        WHERE tr.class_id = :cid
        ORDER BY tr.test_date DESC
    """), {"cid": class_id}).fetchall()

    # --- 3. Dynamic: filter years available for this class ---
    years = db.session.execute(db.text("""
        SELECT DISTINCT YEAR(test_date) AS year
        FROM test_results
        WHERE class_id = :cid
        ORDER BY year DESC
    """), {"cid": class_id}).fetchall()

    # --- 4. Dynamic: subjects used by this class ---
    subjects = db.session.execute(db.text("""
        SELECT DISTINCT sub.subject_name
        FROM test_results tr
        JOIN subjects sub ON sub.subject_id = tr.subject_id
        WHERE tr.class_id = :cid
        ORDER BY sub.subject_name
    """), {"cid": class_id}).fetchall()

    # --- 5. Dynamic: list of all students for this class ---
    students = db.session.execute(db.text("""
        SELECT s.student_id, u.full_name
        FROM students s
        JOIN users u ON u.user_id = s.users_user_id
        WHERE s.class_id = :cid
        ORDER BY u.full_name
    """), {"cid": class_id}).fetchall()

    return render_template(
        "admin/results_page.html",
        results=results,
        grade=grade,
        class_name=class_name,
        years=years,
        subjects=subjects,
        students=students,
        active_page="grade"
    )

@app.route("/admin/add_subject", methods=["GET", "POST"])
def admin_add_subject():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "create":
            subject_name = request.form.get("subject_name", "").strip()
            description = request.form.get("description", "").strip()

            if not subject_name:
                flash("Subject name is required.", "danger")
            else:
                new_subject = Subject(
                    subject_name=subject_name,
                    description=description if description else None,
                    is_active=1,
                )
                db.session.add(new_subject)
                db.session.commit()
                log_activity(session["user_id"], f"Created subject {subject_name}")
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
                subject = Subject.query.get(subject_id)
                if subject:
                    subject.subject_name = subject_name
                    subject.description = description if description else None
                    db.session.commit()
                log_activity(session["user_id"], f"Updated subject ID {subject_id}")
                flash("Subject updated successfully.", "success")

        elif action == "deactivate":
            subject_id = request.form.get("subject_id")
            if subject_id:
                subject = Subject.query.get(subject_id)
                if subject:
                    subject.is_active = 0
                    db.session.commit()
                    log_activity(session["user_id"], f"Deactivated subject ID {subject_id}")
                    flash("Subject deactivated.", "success")
            else:
                flash("Invalid subject ID.", "danger")

        elif action == "activate":
            subject_id = request.form.get("subject_id")
            if subject_id:
                subject = Subject.query.get(subject_id)
                if subject:
                    subject.is_active = 1
                    db.session.commit()
                    log_activity(session["user_id"], f"Activated subject ID {subject_id}")
                    flash("Subject activated.", "success")
            else:
                flash("Invalid subject ID.", "danger")

        return redirect(url_for("admin_add_subject"))

    # GET: fetch all subjects with pagination
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    if per_page not in [10, 25, 50, 100]:
        per_page = 10

    subjects_pagination = Subject.query.order_by(Subject.subject_id.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )

    edit_id = request.args.get("edit_id")
    edit_subject = Subject.query.get(edit_id) if edit_id else None
    from_dashboard = request.args.get("from_dashboard")
    active_page = "dashboard" if from_dashboard else "add_subject"
    return render_template(
        "admin/add_subject.html",
        subjects_pagination=subjects_pagination,
        edit_subject=edit_subject,

  
        active_page=active_page,
    )


@app.route("/admin/users")
def admin_users():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))

    # Get pagination parameters
    students_page = request.args.get('students_page', 1, type=int)
    teachers_page = request.args.get('teachers_page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)

    # Provide lists for template
    with app.app_context():
        students_query = (
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
        )
        students_pagination = students_query.paginate(page=students_page, per_page=per_page, error_out=False)
        students = students_pagination.items

        teachers_query = (
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
        )
        teachers_pagination = teachers_query.paginate(page=teachers_page, per_page=per_page, error_out=False)
        teachers = teachers_pagination.items
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
        students_pagination=students_pagination,
        teachers_pagination=teachers_pagination,
        creds_available=creds_available,
        available_classes=available_classes,
        active_subjects=active_subjects,
        active_page="users"
    )


@app.route("/admin/users/create", methods=["POST"])
def admin_create_user_related():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))
    entity = request.form.get("entity") 
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
        category = "success" if u.is_active == 1 else "danger"
        flash(f"User {u.username} has been {status}.", category)
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

@app.route("/admin/admin_total_students")
def admin_total_students():

    # ======================
    # PAGINATION INPUT
    # ======================
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    offset = (page - 1) * per_page

    # ======================
    # BASIC COUNTS
    # ======================
    total_students = db.session.execute(db.text("""
        SELECT COUNT(*) 
        FROM users u
        JOIN students s ON u.user_id = s.users_user_id
        WHERE u.role_id = 3
    """)).scalar()

    total_male_students = db.session.execute(db.text("""
        SELECT COUNT(*) 
        FROM users u
        JOIN students s ON u.user_id = s.users_user_id
        WHERE u.gender = 'Male' AND u.role_id = 3
    """)).scalar()

    total_female_students = db.session.execute(db.text("""
        SELECT COUNT(*) 
        FROM users u
        JOIN students s ON u.user_id = s.users_user_id
        WHERE u.gender = 'Female' AND u.role_id = 3
    """)).scalar()

    # ======================
    # NEW STUDENTS THIS MONTH
    # ======================
    new_students_month = db.session.execute(db.text("""
        SELECT COUNT(*) 
        FROM users u
        JOIN students s ON u.user_id = s.users_user_id
        WHERE u.role_id = 3
        AND u.created_at IS NOT NULL
        AND MONTH(u.created_at) = MONTH(CURRENT_DATE())
        AND YEAR(u.created_at) = YEAR(CURRENT_DATE())
    """)).scalar() or 0

    # ======================
    # CLASS STATS
    # ======================
    class_rows = db.session.execute(db.text("""
        SELECT class_id, COUNT(*) 
        FROM students
        GROUP BY class_id
        ORDER BY class_id
    """)).fetchall()

    class_labels = [str(row[0]) for row in class_rows]
    class_values = [row[1] for row in class_rows]

    total_classes = len(class_labels)
    avg_students_per_class = round(sum(class_values) / total_classes, 1) if total_classes > 0 else 0

    # ======================
    # TREND CHART
    # ======================
    trend_rows = db.session.execute(db.text("""
        SELECT 
            MONTH(u.created_at) AS month, 
            YEAR(u.created_at) AS year,
            COUNT(*)
        FROM users u
        JOIN students s ON u.user_id = s.users_user_id
        WHERE u.role_id = 3 
        AND u.created_at IS NOT NULL
        GROUP BY YEAR(u.created_at), MONTH(u.created_at)
        ORDER BY YEAR(u.created_at), MONTH(u.created_at)
    """)).fetchall()

    month_names = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    trend_labels = [f"{month_names[row[0]-1]} {row[1]}" for row in trend_rows]
    trend_values = [row[2] for row in trend_rows]

    # ======================
    # PASS / FAIL PLACEHOLDER
    # ======================
    pass_rate = 0
    fail_rate = 0

    # ======================
    # ACTIVE / INACTIVE
    # ======================
    active_students = db.session.execute(db.text("""
        SELECT COUNT(*) 
        FROM users u
        JOIN students s ON u.user_id = s.users_user_id
        WHERE u.is_active = 1 AND u.role_id = 3
    """)).scalar()

    inactive_students = db.session.execute(db.text("""
        SELECT COUNT(*) 
        FROM users u
        JOIN students s ON u.user_id = s.users_user_id
        WHERE u.is_active = 0 AND u.role_id = 3
    """)).scalar()

    # ======================
    # TOTAL STUDENT RECORDS (for pagination)
    # ======================
    total_records = db.session.execute(db.text("""
        SELECT COUNT(*)
        FROM users u
        JOIN students s ON u.user_id = s.users_user_id
        WHERE u.role_id = 3
    """)).scalar()

    # ======================
    # FETCH PAGINATED STUDENT ROWS (WITH CLASS NAME)
    # ======================
    student_rows = db.session.execute(db.text("""
        SELECT 
            u.user_id, 
            u.full_name, 
            u.gender, 
            u.email,
            u.phone, 
            s.student_id, 
            s.class_id,
            c.class_name,
            u.is_active
        FROM users u
        JOIN students s ON u.user_id = s.users_user_id
        LEFT JOIN classes c ON s.class_id = c.class_id
        WHERE u.role_id = 3
        ORDER BY s.student_id ASC
        LIMIT :limit OFFSET :offset
    """), {"limit": per_page, "offset": offset}).fetchall()

    students = [{
        "user_id": r[0],
        "full_name": r[1],
        "gender": r[2],
        "email": r[3],
        "phone": r[4],
        "student_id": r[5],
        "class_id": r[6],
        "class_name": r[7],
        "is_active": r[8],
    } for r in student_rows]

    # ======================
    # GET AVAILABLE CLASSES
    # ======================
    from sqlalchemy import func
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

    # ======================
    # PAGINATION OBJECT
    # ======================
    class Pagination:
        def __init__(self, page, per_page, total):
            self.page = page
            self.per_page = per_page
            self.total = total
            self.pages = (total + per_page - 1) // per_page
            self.has_prev = page > 1
            self.has_next = page < self.pages
            self.prev_num = page - 1
            self.next_num = page + 1

    students_pagination = Pagination(page, per_page, total_records)
# ======================
# RENDER TEMPLATE
# ======================


    return render_template(
        "admin/admin_total_students.html",

        total_students=total_students,
        total_male_students=total_male_students,
        total_female_students=total_female_students,
        new_students_month=new_students_month,

        total_classes=total_classes,
        avg_students_per_class=avg_students_per_class,

        pass_rate=pass_rate,
        fail_rate=fail_rate,

        active_students=active_students,
        inactive_students=inactive_students,

        students=students,
        students_pagination=students_pagination,

        class_labels=class_labels,
        class_values=class_values,

        trend_labels=trend_labels,
        trend_values=trend_values,

        available_classes=available_classes,
        active_page="dashboard",
    )

@app.route("/admin/total_add_students", methods=["POST"])
def total_add_students():
    full_name = request.form.get("full_name")
    gender = request.form.get("gender")
    class_id = request.form.get("class_id") or None
    email = request.form.get("email")
    phone = request.form.get("phone")

    # AUTO USERNAME
    username = email.split("@")[0] if email else full_name.replace(" ", "").lower()

    # DEFAULT PASSWORD
    default_password = "student123"  # you can change this

    new_user = User(
        username=username,
        password=generate_password_hash(default_password),
        full_name=full_name,
        gender=gender,
        email=email,
        phone=phone,
        role_id=3,
        is_active=1,
        force_password_change=0
    )

    db.session.add(new_user)
    db.session.commit()

    new_student = Student(
        users_user_id=new_user.user_id,
        class_id=class_id
    )
    db.session.add(new_student)
    db.session.commit()
    log_activity(session["user_id"], f"Created student {full_name}")

    return redirect(url_for("admin_total_students"))

@app.route("/admin/total_edit_student/<int:user_id>", methods=["POST"])
def admin_edit_total_student(user_id):
    try:
        full_name = request.form.get("full_name")
        gender = request.form.get("gender")
        class_id = request.form.get("class_id") or None
        email = request.form.get("email")
        phone = request.form.get("phone")

        # Update user table
        db.session.execute(db.text("""
            UPDATE users 
            SET full_name = :full_name,
                gender = :gender,
                email = :email,
                phone = :phone
            WHERE user_id = :uid
        """), {
            "full_name": full_name,
            "gender": gender,
            "email": email,
            "phone": phone,
            "uid": user_id
        })

        # Update student table
        db.session.execute(db.text("""
            UPDATE students 
            SET class_id = :class_id
            WHERE users_user_id = :uid
        """), {
            "class_id": class_id,
            "uid": user_id
        })

        db.session.commit()
        flash("Student updated successfully!", "success")

    except Exception as e:
        db.session.rollback()
        print("EDIT STUDENT ERROR:", e)
        flash("Error updating student.", "danger")

    log_activity(session["user_id"], f"Updated student {full_name}")

    return redirect(url_for("admin_total_students"))

@app.route("/admin/student_toggle_status/<int:user_id>", methods=["POST"])
def admin_student_toggle_status(user_id):
    user = User.query.get(user_id)

    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_total_students"))

    user.is_active = 0 if user.is_active else 1
    db.session.commit()

    flash("Student status updated!", "success")
    status = "Activated" if user.is_active else "Deactivated"
    student_name = user.full_name or "Unknown"

    log_activity(session["user_id"], f"{status} student {student_name}")


    return redirect(url_for("admin_total_students"))

@app.route('/admin/admin_total_students/import', methods=['POST'])
def admin_import_students():
    if not is_logged_in() or session.get('role_id') != 1:
        return redirect(url_for('login'))

    file = request.files.get('file')

    if not file:
        flash('Please select a CSV file.', 'danger')
        return redirect(url_for('admin_total_students'))

    filename = file.filename.lower()
    if not filename.endswith('.csv'):
        flash('Only CSV files are supported.', 'warning')
        return redirect(url_for('admin_total_students'))

    stream = io.TextIOWrapper(file.stream, encoding='utf-8')
    reader = csv.DictReader(stream)
    created = 0

    with app.app_context():
        for row in reader:
            full_name = (row.get('full_name') or row.get('name') or 'New User').strip()
            email = (row.get('email') or '').strip() or None
            phone = (row.get('phone') or '').strip() or None
            class_id = (row.get('class_id') or '').strip()

            username = _generate_username(full_name.split()[0])
            temp_pw = _generate_password()

            user = User(
                username=username,
                password=generate_password_hash(temp_pw),
                full_name=full_name,
                email=email,
                phone=phone,
                role_id=3,  # student
                is_active=1,
                force_password_change=1
            )
            db.session.add(user)
            db.session.flush()

            student = Student(
                class_id=int(class_id) if class_id else None,
                users_user_id=user.user_id
            )
            db.session.add(student)

            _add_credential(username, temp_pw, full_name, email or "")
            created += 1

        db.session.commit()

    flash(f"Successfully imported {created} students.", 'success')
    log_activity(session["user_id"], f"Imported {created} students from CSV")

    return redirect(url_for('admin_total_students'))

@app.route("/admin/total_edit_teacher/<int:user_id>", methods=["POST"])
def admin_edit_total_teacher(user_id):
    try:
        full_name = request.form.get("full_name")
        gender = request.form.get("gender")
        email = request.form.get("email")
        phone = request.form.get("phone")
        subject_id = request.form.get("subject_id") or None

        # MULTIPLE CLASS SELECTION
        class_ids = request.form.getlist("class_ids[]")   # <-- FIXED

        db.session.execute(db.text("""
            UPDATE users
            SET full_name = :full_name,
                gender    = :gender,
                email     = :email,
                phone     = :phone
            WHERE user_id = :uid
        """), {
            "full_name": full_name,
            "gender": gender,
            "email": email,
            "phone": phone,
            "uid": user_id
        })

        db.session.execute(db.text("""
            UPDATE teachers
            SET subject_id = :subject_id
            WHERE users_user_id = :uid
        """), {
            "subject_id": subject_id,
            "uid": user_id
        })


        # 1) Remove old assignments
        db.session.execute(db.text("""
            DELETE FROM classes_has_teachers 
            WHERE teachers_teacher_id = (
                SELECT teacher_id FROM teachers WHERE users_user_id = :uid
            )
        """), {"uid": user_id})

        # 2) Insert new assignments (only if user selected any)
        if class_ids:
            for cid in class_ids:
                db.session.execute(db.text("""
                    INSERT INTO classes_has_teachers (classes_class_id, teachers_teacher_id)
                    VALUES (
                        :cid,
                        (SELECT teacher_id FROM teachers WHERE users_user_id = :uid)
                    )
                """), {
                    "cid": cid,
                    "uid": user_id
                })

        db.session.commit()
        flash("Teacher updated successfully!", "success")

    except Exception as e:
        db.session.rollback()
        print("EDIT TEACHER ERROR:", e)
        flash("Error updating teacher.", "danger")
    teacher_name = full_name or "Unknown"
    log_activity(session["user_id"], f"Updated teacher {teacher_name}")


    return redirect(url_for("admin_total_teachers"))

@app.route("/admin/total_add_teacher", methods=["POST"])
def total_add_teacher():
    try:
        full_name = request.form.get("full_name")
        gender = request.form.get("gender")
        email = request.form.get("email")
        phone = request.form.get("phone")
        subject_id = request.form.get("subject_id")
        class_ids = request.form.getlist("class_ids[]")

        # Validate
        if not full_name or not gender or not subject_id:
            flash("Full name, gender, and subject are required.", "danger")
            return redirect(url_for("admin_total_teachers"))


        username = _generate_username(full_name.split()[0])
        temp_pw = _generate_password()
        hashed_pw = generate_password_hash(temp_pw)

        db.session.execute(db.text("""
            INSERT INTO users (username, password, full_name, gender, email, phone, role_id, is_active, force_password_change)
            VALUES (:username, :password, :full_name, :gender, :email, :phone, 2, 1, 1)
        """), {
            "username": username,
            "password": hashed_pw,
            "full_name": full_name,
            "gender": gender,
            "email": email,
            "phone": phone
        })
        db.session.commit()

        # Get new user_id
        user_id = db.session.execute(db.text("SELECT LAST_INSERT_ID()")).scalar()

        db.session.execute(db.text("""
            INSERT INTO teachers (users_user_id, subject_id)
            VALUES (:uid, :sid)
        """), {"uid": user_id, "sid": subject_id})
        db.session.commit()

        # Get teacher_id
        teacher_id = db.session.execute(db.text("""
            SELECT teacher_id FROM teachers WHERE users_user_id = :uid
        """), {"uid": user_id}).scalar()

        for cid in class_ids:
            db.session.execute(db.text("""
                INSERT INTO classes_has_teachers (classes_class_id, teachers_teacher_id)
                VALUES (:cid, :tid)
            """), {"cid": cid, "tid": teacher_id})

        db.session.commit()

        _add_credential(username, temp_pw, full_name, email or "")

        flash("Teacher added successfully!", "success")

    except Exception as e:
        db.session.rollback()
        print("ERROR adding teacher:", e)
        flash("Error adding teacher. Check logs.", "danger")
    log_activity(session["user_id"], f"Created teacher {full_name}")

    return redirect(url_for("admin_total_teachers"))


@app.route("/admin/admin_total_teachers")
def admin_total_teachers():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))

    # Pagination
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    offset = (page - 1) * per_page

    # ---- KPI COUNTS ----
    total_teachers = db.session.execute(db.text("""
        SELECT COUNT(*)
        FROM users u
        JOIN teachers t ON u.user_id = t.users_user_id
        WHERE u.role_id = 2
    """)).scalar()

    male_teachers = db.session.execute(db.text("""
        SELECT COUNT(*)
        FROM users u
        JOIN teachers t ON u.user_id = t.users_user_id
        WHERE u.gender = 'Male' AND u.role_id = 2
    """)).scalar()

    female_teachers = db.session.execute(db.text("""
        SELECT COUNT(*)
        FROM users u
        JOIN teachers t ON u.user_id = t.users_user_id
        WHERE u.gender = 'Female' AND u.role_id = 2
    """)).scalar()

    active_teachers = db.session.execute(db.text("""
        SELECT COUNT(*)
        FROM users u
        JOIN teachers t ON u.user_id = t.users_user_id
        WHERE u.is_active = 1 AND u.role_id = 2
    """)).scalar()

    # ---- TEACHERS PER SUBJECT (CHART) ----
    dept_rows = db.session.execute(db.text("""
        SELECT s.subject_name, COUNT(*)
        FROM teachers t
        LEFT JOIN subjects s ON s.subject_id = t.subject_id
        GROUP BY s.subject_name
    """)).fetchall()

    department_labels = [r[0] or "Unassigned" for r in dept_rows]
    department_values = [r[1] for r in dept_rows]

    # ---- TEACHERS PER GRADE LEVEL (CHART) ----
    grade_rows = db.session.execute(db.text("""
        SELECT c.grade_level, COUNT(*)
        FROM classes_has_teachers cht
        JOIN classes c ON c.class_id = cht.classes_class_id
        GROUP BY c.grade_level
    """)).fetchall()

    grade_level_labels = [str(r[0]) for r in grade_rows]
    grade_level_values = [r[1] for r in grade_rows]

    # ---- PAGINATED TABLE QUERY (NO MORE ONLY_FULL_GROUP_BY ERROR) ----
    teacher_rows = db.session.execute(db.text("""
        SELECT
            t.teacher_id,

            MAX(u.user_id)        AS user_id,
            MAX(u.full_name)      AS full_name,
            MAX(u.gender)         AS gender,
            MAX(u.email)          AS email,
            MAX(u.phone)          AS phone,
            MAX(u.is_active)      AS is_active,
            MAX(s.subject_name)   AS subject_name,

            GROUP_CONCAT(c.class_name ORDER BY c.class_name SEPARATOR ',') AS class_names,
            GROUP_CONCAT(c.class_id   ORDER BY c.class_id   SEPARATOR ',') AS class_ids

        FROM teachers t
        JOIN users u ON u.user_id = t.users_user_id
        LEFT JOIN subjects s ON s.subject_id = t.subject_id
        LEFT JOIN classes_has_teachers cht ON cht.teachers_teacher_id = t.teacher_id
        LEFT JOIN classes c ON c.class_id = cht.classes_class_id

        WHERE u.role_id = 2
        GROUP BY t.teacher_id
        ORDER BY t.teacher_id ASC
        LIMIT :limit OFFSET :offset
    """), {"limit": per_page, "offset": offset}).fetchall()

    # ---- Convert SQL rows to Python dictionaries ----
    teachers = []
    for r in teacher_rows:
        teachers.append({
            "teacher_id": r.teacher_id,
            "user_id": r.user_id,
            "full_name": r.full_name,
            "gender": r.gender,
            "email": r.email,
            "phone": r.phone,
            "is_active": r.is_active,
            "subject_name": r.subject_name,

            # classes
            "classes": r.class_names.split(",") if r.class_names else [],
            "class_ids": [int(x) for x in r.class_ids.split(",")] if r.class_ids else []
        })

    # ---- Pagination helper ----
    class Pagination:
        def __init__(self, page, per_page, total):
            self.page = page
            self.per_page = per_page
            self.total = total
            self.pages = (total + per_page - 1) // per_page
            self.has_prev = page > 1
            self.has_next = page < self.pages
            self.prev_num = page - 1
            self.next_num = page + 1

    teachers_pagination = Pagination(page, per_page, total_teachers)

    # Dropdown data
    subjects = Subject.query.all()
    classes = Class.query.all()


    return render_template(
        "admin/admin_total_teachers.html",

        teachers=teachers,
        teachers_pagination=teachers_pagination,

        # KPI
        total_teachers=total_teachers,
        male_teachers=male_teachers,
        female_teachers=female_teachers,
        active_teachers=active_teachers,

        # charts
        department_labels=department_labels,
        department_values=department_values,
        grade_level_labels=grade_level_labels,
        grade_level_values=grade_level_values,

        # form dropdowns
        subjects=subjects,
        classes=classes,

        # ⭐ FIX: highlight sidebar under "Users"
        active_page="dashboard",


    )

@app.route("/admin/teachers/edit/<int:user_id>", methods=["POST"])
def admin_edit_teacher_post(user_id):
    try:
        user = User.query.get_or_404(user_id)

        # Update general user info
        user.full_name = request.form.get("full_name")
        user.email = request.form.get("email")
        user.phone = request.form.get("phone")
        user.gender = request.form.get("gender")

        subject_id = request.form.get("subject_id")
        class_ids = request.form.getlist("class_ids[]")  # MULTIPLE CLASSES

        teacher = user.teacher_profile
        if teacher:
            teacher.subject_id = subject_id

            # Remove old class assignments
            db.session.execute(db.text("""
                DELETE FROM classes_has_teachers
                WHERE teachers_teacher_id = :tid
            """), {"tid": teacher.teacher_id})

            # Insert ALL selected classes
            for cid in class_ids:
                db.session.execute(db.text("""
                    INSERT INTO classes_has_teachers (classes_class_id, teachers_teacher_id)
                    VALUES (:cid, :tid)
                """), {"cid": cid, "tid": teacher.teacher_id})

        db.session.commit()
        flash("Teacher updated successfully!", "success")

    except Exception as e:
        db.session.rollback()
        print("EDIT TEACHER ERROR:", e)
        flash("Error updating teacher.", "danger")

    return redirect(url_for("admin_total_teachers"))

@app.route("/admin/teacher_toggle_status/<int:teacher_id>", methods=["POST"])
def admin_toggle_teacher_status(teacher_id):
    teacher = Teacher.query.get(teacher_id)
    if not teacher:
        flash("Teacher not found.", "danger")
        return redirect(url_for("admin_total_teachers"))

    user = User.query.get(teacher.users_user_id)
    if not user:
        flash("User not found.", "danger")
        return redirect(url_for("admin_total_teachers"))

    # Toggle active/inactive
    user.is_active = 0 if user.is_active else 1
    db.session.commit()

    flash("Teacher status updated successfully!", "success")
    status = "Activated" if user.is_active else "Deactivated"
    teacher_name = user.full_name
    log_activity(session["user_id"], f"{status} teacher {teacher_name}")


    return redirect(url_for("admin_total_teachers"))


@app.route("/admin/create_teacher", methods=["POST"])
def admin_create_teacher():
    full_name = request.form["full_name"]
    email = request.form.get("email")
    phone = request.form.get("phone")
    department = request.form.get("department")

    username = _generate_username(full_name.split()[0])
    temp_pw = _generate_password()

    new_user = User(
        username=username,
        password=generate_password_hash(temp_pw),
        full_name=full_name,
        email=email,
        phone=phone,
        role_id=2,
        gender="N/A",
        is_active=1,
        force_password_change=1
    )
    db.session.add(new_user)
    db.session.commit()

    new_teacher = Teacher(
        users_user_id=new_user.user_id,
        subject_id=None
    )
    db.session.add(new_teacher)
    db.session.commit()

    subject = Subject.query.filter_by(subject_name=department).first()
    if subject:
        new_teacher.subject_id = subject.subject_id
        db.session.commit()

    _add_credential(username, temp_pw, full_name, email or "")
    flash("Teacher created successfully.", "success")

    return redirect(url_for("admin_total_teachers"))

@app.route('/admin/admin_total_teachers/import', methods=['POST'])
def admin_import_teachers():
    if not is_logged_in() or session.get('role_id') != 1:
        return redirect(url_for('login'))

    file = request.files.get('file')

    if not file:
        flash('Please select a CSV file.', 'danger')
        return redirect(url_for('admin_total_teachers'))

    filename = file.filename.lower()
    if not filename.endswith('.csv'):
        flash('Only CSV files are supported.', 'warning')
        return redirect(url_for('admin_total_teachers'))

    stream = io.TextIOWrapper(file.stream, encoding='utf-8')
    reader = csv.DictReader(stream)
    created = 0

    with app.app_context():
        for row in reader:
            full_name = (row.get('full_name') or row.get('name') or 'New Teacher').strip()
            email = (row.get('email') or '').strip() or None
            phone = (row.get('phone') or '').strip() or None
            subject_name = (row.get('subject') or '').strip()
            class_name = (row.get('class') or '').strip()

            # Convert subject name → subject_id
            subject = Subject.query.filter_by(subject_name=subject_name).first()
            subject_id = subject.subject_id if subject else None

            # Convert class name → class_id
            class_obj = Class.query.filter_by(class_name=class_name).first()
            class_id = class_obj.class_id if class_obj else None

            username = _generate_username(full_name.split()[0])
            temp_pw = _generate_password()

            # Create User
            user = User(
                username=username,
                password=generate_password_hash(temp_pw),
                full_name=full_name,
                email=email,
                phone=phone,
                gender="N/A",
                role_id=2,
                is_active=1,
                force_password_change=1
            )
            db.session.add(user)
            db.session.flush()

            # Create Teacher
            teacher = Teacher(
                users_user_id=user.user_id,
                subject_id=subject_id
            )
            db.session.add(teacher)
            db.session.flush()

            # Assign class if provided
            if class_id:
                db.session.execute(db.text("""
                    INSERT INTO classes_has_teachers (classes_class_id, teachers_teacher_id)
                    VALUES (:cid, :tid)
                """), { "cid": class_id, "tid": teacher.teacher_id })

            _add_credential(username, temp_pw, full_name, email or "")
            created += 1

        db.session.commit()

    flash(f"Successfully imported {created} teachers.", 'success')
    log_activity(session["user_id"], f"Imported {created} teachers from CSV")

    return redirect(url_for('admin_total_teachers'))


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
    # Use the existing teacher dashboard template
    return render_template("teacher/dashboard.html", active_page="dashboard")


@app.route("/teacher/students")
def teacher_students():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    return render_template("teacher/students.html", active_page="students")


@app.route("/teacher/report")
def teacher_report():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    return render_template("teacher/report.html", active_page="report")


@app.route("/teacher/test_creation")
def teacher_test_creation():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    return render_template("teacher/test_creation.html", active_page="tests")


@app.route("/teacher/grade")
def teacher_grade():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    # Render the available grades page (template is named grades.html)
    return render_template("teacher/grades.html", active_page="grade")


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

@app.route("/admin/manage_grades", methods=["GET"])
def admin_manage_grades():

    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))

    teacher_filter = request.args.get("teacher")
    year_filter = request.args.get("year")

    query = """
        SELECT 
            c.class_id, 
            c.class_name, 
            c.grade_level, 
            c.academic_year,

            -- Student Count
            (SELECT COUNT(*) FROM students s WHERE s.class_id = c.class_id) AS student_count,

            -- Teacher Names assigned to the class
            (
                SELECT GROUP_CONCAT(DISTINCT u.full_name SEPARATOR ', ')
                FROM classes_has_teachers cht
                JOIN teachers t ON t.teacher_id = cht.teachers_teacher_id
                JOIN users u ON u.user_id = t.users_user_id
                WHERE cht.classes_class_id = c.class_id
            ) AS teacher_names,

            -- ⭐ SUBJECTS TAUGHT BY TEACHERS OF THIS CLASS
            (
                SELECT GROUP_CONCAT(DISTINCT sub.subject_name ORDER BY sub.subject_name SEPARATOR ', ')
                FROM classes_has_teachers cht
                JOIN teachers t ON t.teacher_id = cht.teachers_teacher_id
                JOIN subjects sub ON sub.subject_id = t.subject_id
                WHERE cht.classes_class_id = c.class_id
            ) AS teacher_subjects,

            -- Next test date
            (
                SELECT MIN(test_date)
                FROM test_results tr
                WHERE tr.class_id = c.class_id
            ) AS next_test_date

        FROM classes c
        WHERE c.is_active = 1
    """

    params = {}

    if teacher_filter:
        query += """
            AND c.class_id IN (
                SELECT classes_class_id 
                FROM classes_has_teachers cht
                JOIN teachers t ON t.teacher_id = cht.teachers_teacher_id
                JOIN users u ON u.user_id = t.users_user_id
                WHERE u.full_name = :teacher
            )
        """
        params["teacher"] = teacher_filter

    if year_filter:
        query += " AND c.academic_year = :year"
        params["year"] = year_filter

    query += " ORDER BY c.grade_level, c.class_name"

    rows = db.session.execute(db.text(query), params).fetchall()

    grades = {}
    for r in rows:
        if r.grade_level not in grades:
            grades[r.grade_level] = []

        grades[r.grade_level].append({
            "class_id": r.class_id,
            "class_name": r.class_name,
            "grade_level": r.grade_level,
            "student_count": r.student_count,
            "academic_year": r.academic_year,
            "teacher_names": r.teacher_names,
            "next_test_date": r.next_test_date,
            "teacher_subjects": r.teacher_subjects.split(", ") if r.teacher_subjects else []
        })

    # Teacher Dropdown
    teachers = db.session.execute(db.text("""
        SELECT DISTINCT u.full_name
        FROM teachers t
        JOIN users u ON u.user_id = t.users_user_id
        WHERE u.is_active = 1
        ORDER BY u.full_name
    """)).fetchall()

    # Year Dropdown
    years = db.session.execute(db.text("""
        SELECT DISTINCT academic_year
        FROM classes
        ORDER BY academic_year DESC
    """)).fetchall()

    return render_template(
        "admin/grade.html",
        grades=grades,
        teachers=teachers,
        years=years,
        teacher_filter=teacher_filter,
        year_filter=year_filter,
        active_page="grade"
    )



@app.route("/admin/assign_test", methods=["GET", "POST"])
def admin_assign_test():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))

    class_id = request.args.get("class_id", type=int)
    if not class_id:
        return "Missing class_id", 400


    class_info = db.session.execute(db.text("""
        SELECT class_name, grade_level, academic_year
        FROM classes 
        WHERE class_id = :cid
    """), {"cid": class_id}).fetchone()

    if not class_info:
        return "Class not found", 404

    subjects = db.session.execute(db.text("""
        SELECT DISTINCT s.subject_id, s.subject_name
        FROM subjects_has_classes shc
        JOIN subjects s 
            ON s.subject_id = shc.subjects_subject_id
        JOIN classes_has_teachers cht
            ON cht.classes_class_id = shc.classes_class_id
        JOIN teachers t
            ON t.teacher_id = cht.teachers_teacher_id
            AND t.subject_id = s.subject_id
        WHERE shc.classes_class_id = :cid
        ORDER BY s.subject_name ASC
    """), {"cid": class_id}).fetchall()

    teachers = db.session.execute(db.text("""
        SELECT t.teacher_id, u.full_name, t.subject_id
        FROM classes_has_teachers cht
        JOIN teachers t ON t.teacher_id = cht.teachers_teacher_id
        JOIN users u ON u.user_id = t.users_user_id
        WHERE cht.classes_class_id = :cid
        ORDER BY u.full_name ASC
    """), {"cid": class_id}).fetchall()

    quizzes = db.session.execute(db.text("""
        SELECT 
            q.quiz_id,
            q.title,
            q.exam_type,
            q.percentage_weight,
            q.start_time,
            q.end_time,
            s.subject_name,
            COALESCE(u.full_name, 'N/A') AS teacher_name
        FROM quizzes q
        JOIN subjects s ON s.subject_id = q.subject_id
        LEFT JOIN teachers t ON t.teacher_id = q.teacher_id
        LEFT JOIN users u ON u.user_id = t.users_user_id
        WHERE q.class_id = :cid
        ORDER BY q.start_time DESC
    """), {"cid": class_id}).fetchall()

    if request.method == "POST":

        form = request.form
        subject_id = form.get("subject_id")
        teacher_id = form.get("teacher_id")
        title = form.get("title")
        exam_type = form.get("exam_type")
        percentage = form.get("percentage_weight", "").replace("%", "").strip()
        start = form.get("start_time")
        end = form.get("end_time")

        # Validation
        missing = [name for name, val in {
            "Subject": subject_id,
            "Teacher": teacher_id,
            "Title": title,
            "Exam Type": exam_type,
            "Percentage Weight": percentage,
            "Start Time": start,
            "End Time": end
        }.items() if not val]

        if missing:
            flash(f"Missing: {', '.join(missing)}", "danger")
            return redirect(url_for("admin_assign_test", class_id=class_id))

        # Insert exam
        db.session.execute(db.text("""
            INSERT INTO quizzes 
                (title, class_id, subject_id, teacher_id,
                 exam_type, percentage_weight,
                 start_time, end_time, is_active, created_by)
            VALUES 
                (:title, :class_id, :subject_id, :teacher_id,
                 :exam_type, :percentage_weight,
                 :start_time, :end_time, 1, :created_by)
        """), {
            "title": title,
            "class_id": class_id,
            "subject_id": subject_id,
            "teacher_id": teacher_id,
            "exam_type": exam_type,
            "percentage_weight": percentage,
            "start_time": start,
            "end_time": end,
            "created_by": session.get("user_id")
        })

        db.session.commit()
        flash("Examination assigned successfully!", "success")
        return redirect(url_for("admin_assign_test", class_id=class_id))

    return render_template(
        "admin/assign_test.html",
        class_info=class_info,
        subjects=subjects,
        teachers=teachers,
        quizzes=quizzes
    )

@app.route("/results/<grade>/<class_name>")
def class_results(grade, class_name):
    # later you can load results from DB here
    return render_template("admin/results_page.html", grade=grade, class_name=class_name)
def log_activity(user_id, action):
    """Store activity with clean formatted user name and role."""

    try:
        # Get actor name (Admin / Teacher / Student)
        user = User.query.get(user_id)
        actor_name = user.full_name if user else "Unknown User"

        # Final formatted text stored in DB
        final_action = f"{action}."

        db.session.execute(db.text("""
            INSERT INTO activity_logs (user_id, action)
            VALUES (:user_id, :action)
        """), {
            "user_id": user_id,
            "action": final_action
        })

        db.session.commit()

    except Exception as e:
        print("Activity Log Error:", e)
        db.session.rollback()
        
@app.route("/admin/get_classes/<grade>")
def get_classes(grade):
    rows = db.session.execute(db.text("""
        SELECT class_id, class_name
        FROM classes
        WHERE grade_level = :grade AND is_active = 1
        ORDER BY class_name ASC
    """), {"grade": grade}).fetchall()

    return jsonify([
        {"id": r.class_id, "name": r.class_name}
        for r in rows
    ])

if __name__ == "__main__":
    app.run(debug=True)
