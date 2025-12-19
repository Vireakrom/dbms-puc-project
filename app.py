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

    # Real data pipeline
    grade_filter = (request.args.get("grade") or "").strip()
    class_filter = (request.args.get("class") or "").strip()
    subject_filter = (request.args.get("subject") or "").strip()
    year_filter = (request.args.get("year") or "").strip()
    term_filter = (request.args.get("term") or "").strip()

    # Reference data for filters
    classes = Class.query.filter_by(is_active=1).order_by(Class.grade_level, Class.class_name).all()
    subjects = Subject.query.filter_by(is_active=1).order_by(Subject.subject_name).all()

    # If class filter is provided but not valid, reset to "all"
    if class_filter:
        valid_class_names = {c.class_name for c in classes}
        if class_filter not in valid_class_names:
            class_filter = ""

    academic_year_rows = db.session.execute(db.text("""
        SELECT DISTINCT academic_year
        FROM classes
        WHERE academic_year IS NOT NULL AND academic_year <> ''
        ORDER BY academic_year DESC
    """)).fetchall()
    academic_years = [r.academic_year for r in academic_year_rows]

    # Build test result query with filters
    query = db.text(
        """
        SELECT
            tr.result_id,
            tr.test_date,
            tr.quiz_score,
            tr.total_score,
            tr.grade,
            tr.student_id,
            tr.class_id,
            tr.subject_id,
            st.student_id AS sid,
            u.full_name,
            u.username,
            c.class_name,
            c.grade_level,
            c.academic_year,
            sub.subject_name
        FROM test_results tr
        JOIN students st ON st.student_id = tr.student_id
        JOIN users u ON u.user_id = st.users_user_id
        LEFT JOIN classes c ON c.class_id = tr.class_id
        LEFT JOIN subjects sub ON sub.subject_id = tr.subject_id
        WHERE 1=1
        """
    )

    params = {}
    conditions = []
    if grade_filter:
        conditions.append("AND c.grade_level = :grade")
        params["grade"] = grade_filter
    if class_filter:
        conditions.append("AND c.class_name = :class_name")
        params["class_name"] = class_filter
    if subject_filter:
        conditions.append("AND sub.subject_name = :subject_name")
        params["subject_name"] = subject_filter
    if year_filter:
        conditions.append("AND (c.academic_year = :year)")
        params["year"] = year_filter
    # term_filter is ignored because test_results is not linked to quiz_id in the schema

    if conditions:
        query = db.text(query.text + " " + " ".join(conditions))

    query = db.text(query.text + " ORDER BY tr.test_date DESC, tr.result_id DESC")

    rows = db.session.execute(query, params).fetchall()

    # Summary metrics (prefer tr.total_score when available; fall back to tr.quiz_score)
    scores = []
    for r in rows:
        if getattr(r, 'total_score', None) is not None:
            try:
                scores.append(float(r.total_score))
            except (TypeError, ValueError):
                continue
        elif getattr(r, 'quiz_score', None) is not None:
            try:
                scores.append(float(r.quiz_score))
            except (TypeError, ValueError):
                continue
    total_results = len(scores)
    total_students = len({r.student_id for r in rows})
    average_score = round(sum(scores) / total_results, 1) if total_results else 0.0
    pass_count = sum(1 for s in scores if s >= 60)
    top_performers = sum(1 for s in scores if s >= 90)
    need_support = sum(1 for s in scores if s < 60)
    pass_rate = round((pass_count / total_results) * 100, 1) if total_results else 0.0

    # Grade distribution buckets (based on the same score list)
    dist_buckets = {
        "A (90-100)": {"count": 0, "color": "#10b981", "min": 90},
        "B (80-89)": {"count": 0, "color": "#3b82f6", "min": 80},
        "C (70-79)": {"count": 0, "color": "#f59e0b", "min": 70},
        "D (60-69)": {"count": 0, "color": "#f97316", "min": 60},
        "F (<60)": {"count": 0, "color": "#ef4444", "min": 0},
    }
    for s in scores:
        if s >= 90:
            dist_buckets["A (90-100)"]["count"] += 1
        elif s >= 80:
            dist_buckets["B (80-89)"]["count"] += 1
        elif s >= 70:
            dist_buckets["C (70-79)"]["count"] += 1
        elif s >= 60:
            dist_buckets["D (60-69)"]["count"] += 1
        else:
            dist_buckets["F (<60)"]["count"] += 1

    grade_distribution = []
    for label, info in dist_buckets.items():
        count = info["count"]
        percent = round((count / total_results) * 100, 1) if total_results else 0
        grade_distribution.append({
            "label": label,
            "percent": percent,
            "count": count,
            "color": info["color"],
        })

    # Grade distribution buckets
    dist_buckets = {
        "A (90-100)": {"count": 0, "color": "#10b981", "min": 90},
        "B (80-89)": {"count": 0, "color": "#3b82f6", "min": 80},
        "C (70-79)": {"count": 0, "color": "#f59e0b", "min": 70},
        "D (60-69)": {"count": 0, "color": "#f97316", "min": 60},
        "F (<60)": {"count": 0, "color": "#ef4444", "min": 0},
    }
    for s in scores:
        if s >= 90:
            dist_buckets["A (90-100)"]["count"] += 1
        elif s >= 80:
            dist_buckets["B (80-89)"]["count"] += 1
        elif s >= 70:
            dist_buckets["C (70-79)"]["count"] += 1
        elif s >= 60:
            dist_buckets["D (60-69)"]["count"] += 1
        else:
            dist_buckets["F (<60)"]["count"] += 1

    grade_distribution = []
    for label, info in dist_buckets.items():
        count = info["count"]
        percent = round((count / total_results) * 100, 1) if total_results else 0
        grade_distribution.append({
            "label": label,
            "percent": percent,
            "count": count,
            "color": info["color"],
        })

    # Subject-wise averages (prefer total_score when present)
    subject_scores = {}
    for r in rows:
        score_val = None
        if getattr(r, 'total_score', None) is not None:
            try:
                score_val = float(r.total_score)
            except (TypeError, ValueError):
                score_val = None
        elif getattr(r, 'quiz_score', None) is not None:
            try:
                score_val = float(r.quiz_score)
            except (TypeError, ValueError):
                score_val = None
        if score_val is None:
            continue
        subject_scores.setdefault(r.subject_name or "Unknown", []).append(score_val)
    subject_averages = {
        k: round(sum(v) / len(v), 1)
        for k, v in subject_scores.items()
    }

    # Performance trend by grade level (prefer total_score when present)
    grade_scores = {}
    for r in rows:
        score_val = None
        if getattr(r, 'total_score', None) is not None:
            try:
                score_val = float(r.total_score)
            except (TypeError, ValueError):
                score_val = None
        elif getattr(r, 'quiz_score', None) is not None:
            try:
                score_val = float(r.quiz_score)
            except (TypeError, ValueError):
                score_val = None
        if score_val is None:
            continue
        key = f"Grade {r.grade_level}" if r.grade_level else "Ungraded"
        grade_scores.setdefault(key, []).append(score_val)

    performance_trend = {
        "labels": list(grade_scores.keys()),
        "values": [round(sum(vals) / len(vals), 1) for vals in grade_scores.values()],
    }

    # Sample results table data (latest 50) — show total_score when available
    sample_results = []
    for r in rows[:50]:
        if getattr(r, 'total_score', None) is not None:
            try:
                score_val = float(r.total_score)
            except (TypeError, ValueError):
                score_val = None
        elif getattr(r, 'quiz_score', None) is not None:
            try:
                score_val = float(r.quiz_score)
            except (TypeError, ValueError):
                score_val = None
        else:
            score_val = None

        grade_val = r.grade if r.grade is not None else score_val
        remarks = "Excellent" if score_val is not None and score_val >= 90 else "Needs support" if score_val is not None and score_val < 60 else "Good"
        sample_results.append({
            "student_id": r.student_id,
            "name": r.full_name or r.username,
            "class_name": r.class_name or "N/A",
            "subject": r.subject_name or "N/A",
            "test_date": r.test_date.strftime("%Y-%m-%d") if r.test_date else "",
            "score": score_val if score_val is not None else "--",
            "grade": grade_val if grade_val is not None else "--",
            "remarks": remarks,
        })

    # Regardless of results rows, compute student count scoped by filters so counts stay consistent
    student_query = db.session.query(Student.student_id).join(User, Student.users_user_id == User.user_id).outerjoin(Class, Student.class_id == Class.class_id)
    if grade_filter:
        student_query = student_query.filter(Class.grade_level == grade_filter)
    if class_filter:
        student_query = student_query.filter(Class.class_name == class_filter)
    if year_filter:
        student_query = student_query.filter(Class.academic_year == year_filter)
    total_students = student_query.filter(User.is_active == 1).distinct().count()

    from_dashboard = request.args.get("from_dashboard")
    active_page = "dashboard" if from_dashboard else "report"
    return render_template(
        "admin/report.html",
        total_students=total_students,
        pass_rate=pass_rate,
        average_score=average_score,
        top_performers=top_performers,
        need_support=need_support,
        classes=classes,
        subjects=subjects,
        academic_years=academic_years,
        sample_results=sample_results,
        grade_distribution=grade_distribution,
        performance_trend=performance_trend,
        subject_averages=subject_averages,
        filters={
            "grade": grade_filter,
            "class": class_filter,
            "subject": subject_filter,
            "year": year_filter,
            "term": term_filter,
        },
        active_page=active_page,
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
    student_class_filter = request.args.get('student_class', type=int)
    teacher_class_filter = request.args.get('teacher_class', type=int)

    # Provide lists for template
    with app.app_context():
        cht = db.Table('classes_has_teachers', db.metadata, autoload_with=db.engine)

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

        if student_class_filter:
            students_query = students_query.filter(Student.class_id == student_class_filter)

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

        if teacher_class_filter:
            teachers_query = (
                teachers_query
                .join(cht, cht.c.teachers_teacher_id == Teacher.teacher_id)
                .filter(cht.c.classes_class_id == teacher_class_filter)
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
    classes_all = Class.query.order_by(Class.grade_level, Class.class_name).all()

    # Map teacher_id -> comma-separated class_ids for edit modal multi-select
    teacher_class_map = {}
    for t in teachers:
        tid = t[1] if len(t) > 1 else None
        if not tid:
            continue
        class_rows = db.session.execute(db.text("""
            SELECT classes_class_id
            FROM classes_has_teachers
            WHERE teachers_teacher_id = :tid
        """), {"tid": tid}).fetchall()
        teacher_class_map[tid] = ",".join(str(r.classes_class_id) for r in class_rows) if class_rows else ""

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
        classes=classes_all,
        teacher_class_map=teacher_class_map,
        student_class_filter=student_class_filter,
        teacher_class_filter=teacher_class_filter,
        active_page="users"
    )


@app.route("/admin/users/create", methods=["POST"])
def admin_create_user_related():
    if not is_logged_in() or session.get("role_id") != 1:
        return redirect(url_for("login"))
    entity = request.form.get("entity")
    if entity not in ("student", "teacher"):
        flash("Invalid role selected.", "danger")
        return redirect(url_for("admin_users"))

    full_name = request.form.get("full_name", "").strip() or "New User"
    gender = request.form.get("gender", "").strip()
    email = request.form.get("email", "").strip() or None
    phone = request.form.get("phone", "").strip() or None
    class_id = request.form.get("class_id")
    subject_id = request.form.get("subject_id")
    teacher_classes = request.form.getlist("class_ids[]") if entity == "teacher" else []

    if not gender:
        flash("Gender is required.", "warning")
        return redirect(url_for("admin_users"))

    if entity == "teacher" and not subject_id:
        flash("Subject is required for teachers.", "warning")
        return redirect(url_for("admin_users"))

    role_id = 3 if entity == "student" else 2
    username = _generate_username(full_name.split()[0] if full_name else entity)
    temp_pw = _generate_password()
    hashed = generate_password_hash(temp_pw)

    try:
        with app.app_context():
            u = User(
                username=username,
                password=hashed,
                full_name=full_name,
                email=email,
                gender=gender,
                role_id=role_id,
                is_active=1,
                phone=phone,
                force_password_change=1
            )
            db.session.add(u)
            db.session.flush()

            if entity == "student":
                s = Student(class_id=int(class_id) if class_id else None, users_user_id=u.user_id)
                db.session.add(s)
            else:
                t = Teacher(subject_id=int(subject_id) if subject_id else None, users_user_id=u.user_id)
                db.session.add(t)
                db.session.flush()

                for cid in teacher_classes:
                    if not cid:
                        continue
                    db.session.execute(db.text("""
                        INSERT INTO classes_has_teachers (classes_class_id, teachers_teacher_id)
                        VALUES (:cid, :tid)
                    """), {"cid": int(cid), "tid": t.teacher_id})

            db.session.commit()
        _add_credential(username, temp_pw, full_name, email or "")
        flash(f"{entity.title()} and user created. Credentials added to one-time list.", "success")
    except Exception as e:
        db.session.rollback()
        flash("Failed to create user.", "danger")
        print("Create user error:", e)

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

            # Update teacher classes
            teacher_classes = request.form.getlist("class_ids[]")
            # First, remove existing associations
            db.session.execute(db.text("""
                DELETE FROM classes_has_teachers WHERE teachers_teacher_id = :tid
            """), {"tid": u.teacher_profile.teacher_id})
            # Then, add new ones
            for cid in teacher_classes:
                if not cid:
                    continue
                db.session.execute(db.text("""
                    INSERT INTO classes_has_teachers (classes_class_id, teachers_teacher_id)
                    VALUES (:cid, :tid)
                """), {"cid": int(cid), "tid": u.teacher_profile.teacher_id})

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


@app.route("/teacher/dashboard/data")
def teacher_dashboard_data():
    """Provide dashboard stats for the logged-in teacher."""
    if not is_logged_in() or session.get("role_id") != 2:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    user_id = session.get("user_id")
    teacher_row = db.session.execute(db.text(
        """
        SELECT teacher_id
        FROM teachers
        WHERE users_user_id = :uid
        """
    ), {"uid": user_id}).fetchone()

    if not teacher_row:
        return jsonify({"ok": False, "error": "Teacher profile not found."}), 404

    teacher_id = teacher_row.teacher_id

    # Classes the teacher handles
    class_rows = db.session.execute(db.text(
        """
        SELECT c.class_id, c.class_name, c.grade_level
        FROM classes c
        JOIN classes_has_teachers cht ON cht.classes_class_id = c.class_id
        WHERE cht.teachers_teacher_id = :tid AND c.is_active = 1
        ORDER BY c.grade_level, c.class_name
        """
    ), {"tid": teacher_id}).fetchall()

    total_classes = len(class_rows)

    # Summary counts
    student_count_row = db.session.execute(db.text(
        """
        SELECT COUNT(DISTINCT s.student_id) AS total_students
        FROM students s
        JOIN classes_has_teachers cht ON cht.classes_class_id = s.class_id
        WHERE cht.teachers_teacher_id = :tid
        """
    ), {"tid": teacher_id}).fetchone()
    total_students = student_count_row.total_students if student_count_row else 0

    totals_row = db.session.execute(db.text(
        """
        SELECT
            (SELECT COUNT(*) FROM quizzes q WHERE q.teacher_id = :tid) AS total_tests,
            (SELECT COUNT(*) FROM test_results tr WHERE tr.teacher_id = :tid) AS total_results
        """
    ), {"tid": teacher_id}).fetchone()

    total_tests = totals_row.total_tests if totals_row else 0
    total_results = totals_row.total_results if totals_row else 0

    # Upcoming tests (future start times)
    upcoming = db.session.execute(db.text(
        """
        SELECT
            q.quiz_id,
            q.title,
            q.start_time,
            q.end_time,
            c.class_name,
            s.subject_name
        FROM quizzes q
        JOIN classes c ON c.class_id = q.class_id
        JOIN subjects s ON s.subject_id = q.subject_id
        WHERE q.teacher_id = :tid
          AND q.is_active = 1
          AND q.start_time >= NOW()
        ORDER BY q.start_time ASC
        LIMIT 5
        """
    ), {"tid": teacher_id}).fetchall()

    upcoming_tests = [
        {
            "quiz_id": r.quiz_id,
            "title": r.title,
            "class_name": r.class_name,
            "subject_name": r.subject_name,
            "start_time": r.start_time.isoformat() if r.start_time else None,
            "end_time": r.end_time.isoformat() if r.end_time else None,
        }
        for r in upcoming
    ]

    # Recent test results (latest submissions)
    recent_rows = db.session.execute(db.text(
        """
        SELECT
            tr.result_id,
            tr.test_date,
            tr.quiz_score,
            tr.grade,
            u.full_name AS student_name,
            c.class_name,
            s.subject_name
        FROM test_results tr
        JOIN students st ON st.student_id = tr.student_id
        JOIN users u ON u.user_id = st.users_user_id
        JOIN classes c ON c.class_id = tr.class_id
        JOIN subjects s ON s.subject_id = tr.subject_id
        WHERE tr.teacher_id = :tid
        ORDER BY tr.test_date DESC
        LIMIT 5
        """
    ), {"tid": teacher_id}).fetchall()

    recent_results = []
    for r in recent_rows:
        grade_val = r.grade if r.grade is not None else r.quiz_score
        recent_results.append({
            "result_id": r.result_id,
            "student_name": r.student_name,
            "class_name": r.class_name,
            "subject_name": r.subject_name,
            "score": float(r.quiz_score) if r.quiz_score is not None else None,
            "grade": float(grade_val) if isinstance(grade_val, (int, float)) else grade_val,
            "test_date": r.test_date.isoformat() if r.test_date else None,
        })

    # Pass / fail by class for chart
    pass_fail_rows = db.session.execute(db.text(
        """
        SELECT
            c.class_name,
            SUM(CASE WHEN tr.quiz_score >= 60 THEN 1 ELSE 0 END) AS pass_count,
            SUM(CASE WHEN tr.quiz_score < 60 THEN 1 ELSE 0 END) AS fail_count
        FROM classes c
        JOIN classes_has_teachers cht ON cht.classes_class_id = c.class_id
        LEFT JOIN test_results tr ON tr.class_id = c.class_id AND tr.teacher_id = :tid
        WHERE cht.teachers_teacher_id = :tid AND c.is_active = 1
        GROUP BY c.class_id, c.class_name
        ORDER BY c.grade_level, c.class_name
        """
    ), {"tid": teacher_id}).fetchall()

    pass_fail = [
        {
            "class_name": r.class_name,
            "pass_count": int(r.pass_count or 0),
            "fail_count": int(r.fail_count or 0),
        }
        for r in pass_fail_rows
    ]

    # Tests distribution by grade level
    tests_by_grade_rows = db.session.execute(db.text(
        """
        SELECT
            c.grade_level,
            COUNT(q.quiz_id) AS test_count
        FROM classes c
        JOIN classes_has_teachers cht ON cht.classes_class_id = c.class_id
        LEFT JOIN quizzes q ON q.class_id = c.class_id AND q.teacher_id = :tid
        WHERE cht.teachers_teacher_id = :tid AND c.is_active = 1
        GROUP BY c.grade_level
        ORDER BY c.grade_level
        """
    ), {"tid": teacher_id}).fetchall()

    tests_by_grade = [
        {
            "grade_level": r.grade_level,
            "test_count": int(r.test_count or 0),
        }
        for r in tests_by_grade_rows
    ]

    payload = {
        "summary": {
            "total_students": int(total_students or 0),
            "total_classes": int(total_classes or 0),
            "total_tests": int(total_tests or 0),
            "total_results": int(total_results or 0),
        },
        "upcoming_tests": upcoming_tests,
        "recent_results": recent_results,
        "pass_fail": pass_fail,
        "tests_by_grade": tests_by_grade,
    }

    return jsonify({"ok": True, "data": payload})


@app.route("/teacher/students")
def teacher_students():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    user_id = session.get("user_id")
    teacher_row = db.session.execute(db.text("""
        SELECT teacher_id
        FROM teachers
        WHERE users_user_id = :uid
    """), {"uid": user_id}).fetchone()

    if not teacher_row:
        flash("Teacher profile not found. Please contact the administrator to link your teacher profile.", "danger")
        return redirect(url_for("teacher_dashboard"))

    classes = db.session.execute(db.text("""
        SELECT c.class_id, c.class_name, c.grade_level
        FROM classes c
        JOIN classes_has_teachers cht ON cht.classes_class_id = c.class_id
        WHERE cht.teachers_teacher_id = :tid AND c.is_active = 1
        ORDER BY c.grade_level, c.class_name
    """), {"tid": teacher_row.teacher_id}).fetchall()

    class_list = [{"class_id": r.class_id, "class_name": r.class_name, "grade_level": r.grade_level} for r in classes]

    selected_class_id = request.args.get("class_id", type=int) or (class_list[0]["class_id"] if class_list else None)

    students = []
    if selected_class_id:
        students = db.session.execute(db.text("""
            SELECT s.student_id, s.class_id, u.full_name, u.username, u.email
            FROM students s
            JOIN users u ON u.user_id = s.users_user_id
            WHERE s.class_id = :cid
            ORDER BY u.full_name
        """), {"cid": selected_class_id}).fetchall()

    return render_template(
        "teacher/students.html",
        active_page="students",
        classes=class_list,
        selected_class_id=selected_class_id,
        students=students
    )


@app.route("/teacher/report")
def teacher_report():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    return render_template("teacher/report.html", active_page="report")


@app.route("/teacher/report/data")
def teacher_report_data():
    """Return grade/test results for the logged-in teacher."""
    try:
        if not is_logged_in() or session.get("role_id") != 2:
            return jsonify({"ok": False, "error": "Unauthorized"}), 401

        user_id = session.get("user_id")
        teacher_row = db.session.execute(db.text(
            """
            SELECT teacher_id
            FROM teachers
            WHERE users_user_id = :uid
            """
        ), {"uid": user_id}).fetchone()

        if not teacher_row:
            return jsonify({"ok": False, "error": "Teacher profile not found."}), 404

        search = (request.args.get("search") or "").strip().lower()

        query = """
            SELECT
                tr.result_id,
                tr.test_date,
                tr.quiz_score,
                tr.grade,
                sub.subject_name,
                c.class_name,
                u.full_name AS student_name
            FROM test_results tr
            JOIN students s ON s.student_id = tr.student_id
            JOIN users u ON u.user_id = s.users_user_id
            JOIN subjects sub ON sub.subject_id = tr.subject_id
            JOIN classes c ON c.class_id = tr.class_id
            WHERE tr.teacher_id = :tid
        """

        params = {"tid": teacher_row.teacher_id}

        if search:
            query += " AND LOWER(u.full_name) LIKE :search"
            params["search"] = f"%{search}%"

        query += " ORDER BY tr.test_date DESC, u.full_name"

        rows = db.session.execute(db.text(query), params).fetchall()

        results = []
        for r in rows:
            # Grade may be a letter (generated column) or numeric; avoid forcing float on letters
            grade_value = r.grade if r.grade is not None else r.quiz_score
            test_label = r.subject_name
            if r.class_name:
                test_label = f"{test_label} ({r.class_name})"
            if r.test_date:
                test_label = f"{test_label} on {r.test_date.strftime('%Y-%m-%d')}"

            results.append({
                "id": r.result_id,
                "name": r.student_name,
                "title": test_label,
                "grade": float(grade_value) if isinstance(grade_value, (int, float)) else grade_value,
                "subject": r.subject_name,
                "class_name": r.class_name,
                "test_date": r.test_date.isoformat() if r.test_date else None,
            })

        return jsonify({"ok": True, "results": results})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/teacher/test_creation", methods=["GET", "POST"])
def teacher_test_creation():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    teacher_row = db.session.execute(db.text("""
        SELECT teacher_id, subject_id
        FROM teachers
        WHERE users_user_id = :uid
    """), {"uid": user_id}).fetchone()

    if not teacher_row:
        flash("Teacher profile not found. Please contact the administrator to link your teacher profile.", "danger")
        return redirect(url_for("teacher_dashboard"))

    teacher_id = teacher_row.teacher_id

    if request.method == "POST":
        data = request.get_json(silent=True) or {}

        required = {
            "title": data.get("title", "").strip(),
            "subject_id": data.get("subject_id"),
            "class_id": data.get("class_id"),
            "duration": data.get("duration"),
            "testDate": data.get("testDate"),
            "testTime": data.get("testTime"),
        }

        missing = [k for k, v in required.items() if not v and v != 0]
        if missing:
            return jsonify({"ok": False, "error": f"Missing fields: {', '.join(missing)}"}), 400

        try:
            title = required["title"]
            subject_id = int(required["subject_id"])
            class_id = int(required["class_id"])
            duration = int(required["duration"])
            test_date = required["testDate"]
            test_time = required["testTime"]
            start_dt = datetime.strptime(f"{test_date} {test_time}", "%Y-%m-%d %H:%M")
            end_dt = start_dt + timedelta(minutes=duration)
        except Exception:
            return jsonify({"ok": False, "error": "Invalid field types."}), 400

        questions = data.get("questions") or []
        if not questions:
            return jsonify({"ok": False, "error": "At least one question is required."}), 400

        exam_type = data.get("exam_type") or "Quiz"
        percentage_weight = data.get("percentage_weight") or 0

        try:
            result = db.session.execute(db.text("""
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
                "percentage_weight": percentage_weight,
                "start_time": start_dt,
                "end_time": end_dt,
                "created_by": user_id
            })

            quiz_id = result.lastrowid

            for q in questions:
                db.session.execute(db.text("""
                    INSERT INTO quiz_questions 
                        (quiz_id, question_text, option_a, option_b, option_c, option_d, correct_option)
                    VALUES 
                        (:quiz_id, :question_text, :option_a, :option_b, :option_c, :option_d, :correct_option)
                """), {
                    "quiz_id": quiz_id,
                    "question_text": q.get("question", "").strip(),
                    "option_a": q.get("option_a", ""),
                    "option_b": q.get("option_b", ""),
                    "option_c": q.get("option_c", ""),
                    "option_d": q.get("option_d", ""),
                    "correct_option": q.get("correct_option", "")
                })

            db.session.commit()
            log_activity(user_id, f"Created quiz '{title}'")

            meta = db.session.execute(db.text("""
                SELECT c.class_name, c.grade_level, s.subject_name
                FROM classes c
                JOIN subjects s ON s.subject_id = :sid
                WHERE c.class_id = :cid
            """), {"cid": class_id, "sid": subject_id}).fetchone()

            response_quiz = {
                "quiz_id": quiz_id,
                "title": title,
                "class_id": class_id,
                "subject_id": subject_id,
                "class_name": meta.class_name if meta else str(class_id),
                "grade_level": meta.grade_level if meta else "",
                "subject_name": meta.subject_name if meta else "",
                "start_time": start_dt.isoformat(),
                "end_time": end_dt.isoformat(),
                "question_count": len(questions)
            }

            return jsonify({"ok": True, "quiz": response_quiz})
        except Exception as e:
            db.session.rollback()
            return jsonify({"ok": False, "error": str(e)}), 500

    classes = db.session.execute(db.text("""
        SELECT c.class_id, c.class_name, c.grade_level
        FROM classes c
        JOIN classes_has_teachers cht ON cht.classes_class_id = c.class_id
        WHERE cht.teachers_teacher_id = :tid AND c.is_active = 1
        ORDER BY c.grade_level, c.class_name
    """), {"tid": teacher_id}).fetchall()

    class_list = [
        {"class_id": r.class_id, "class_name": r.class_name, "grade_level": r.grade_level}
        for r in classes
    ]

    subject_row = db.session.execute(db.text("""
        SELECT subject_id, subject_name
        FROM subjects
        WHERE subject_id = :sid
    """), {"sid": teacher_row.subject_id}).fetchone()

    subject_data = None
    if subject_row:
        subject_data = {"subject_id": subject_row.subject_id, "subject_name": subject_row.subject_name}

    return render_template(
        "teacher/test_creation.html",
        active_page="tests",
        classes=class_list,
        subject=subject_data
    )


@app.route("/teacher/grade")
def teacher_grade():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))
    # Render the available grades page (template is named grades.html)
    return render_template("teacher/grades.html", active_page="grade")


@app.route("/teacher/grade/data")
def teacher_grade_data():
    if not is_logged_in() or session.get("role_id") != 2:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    user_id = session.get("user_id")
    teacher_row = db.session.execute(db.text("""
        SELECT teacher_id, subject_id
        FROM teachers
        WHERE users_user_id = :uid
    """), {"uid": user_id}).fetchone()

    if not teacher_row:
        return jsonify({"ok": False, "error": "Teacher profile not found."}), 404

    rows = db.session.execute(db.text("""
        SELECT
            c.class_id,
            c.class_name,
            c.grade_level,
            COUNT(DISTINCT s.student_id) AS student_count,
            COUNT(tr.result_id) AS taken_count,
            SUM(CASE WHEN tr.quiz_score >= 60 THEN 1 ELSE 0 END) AS pass_count,
            AVG(tr.quiz_score) AS avg_score,
            MAX(tr.test_date) AS last_test,
            (
                SELECT MIN(q.start_time)
                FROM quizzes q
                WHERE q.class_id = c.class_id
                  AND q.teacher_id = :tid
                  AND q.is_active = 1
                AND q.start_time >= NOW()
            ) AS next_test
        FROM classes c
        JOIN classes_has_teachers cht ON cht.classes_class_id = c.class_id
        LEFT JOIN students s ON s.class_id = c.class_id
        LEFT JOIN test_results tr ON tr.class_id = c.class_id AND tr.teacher_id = :tid
        WHERE cht.teachers_teacher_id = :tid AND c.is_active = 1
        GROUP BY c.class_id, c.class_name, c.grade_level
        ORDER BY c.grade_level, c.class_name
    """), {"tid": teacher_row.teacher_id}).fetchall()

    subject_row = db.session.execute(db.text("""
        SELECT subject_name
        FROM subjects
        WHERE subject_id = :sid
    """), {"sid": teacher_row.subject_id}).fetchone()

    classes = []
    for r in rows:
        taken = r.taken_count or 0
        passed = r.pass_count or 0
        pass_rate = 0
        if taken:
            pass_rate = round((passed / taken) * 100, 2)

        classes.append({
            "class_id": r.class_id,
            "class_name": r.class_name,
            "grade_level": r.grade_level,
            "student_count": r.student_count or 0,
            "taken_count": taken,
            "pass_rate": pass_rate,
            "avg_score": round(float(r.avg_score), 2) if r.avg_score is not None else None,
            "last_test": r.last_test.strftime("%b %d, %Y") if r.last_test else None,
            "next_test": r.next_test.strftime("%b %d, %Y") if r.next_test else None,
            "subject_name": subject_row.subject_name if subject_row else None,
            "subjects": [subject_row.subject_name] if subject_row else []
        })

    return jsonify({"ok": True, "classes": classes})


@app.route("/teacher/tests", methods=["GET"])
def teacher_tests():
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    teacher_row = db.session.execute(db.text("""
        SELECT teacher_id
        FROM teachers
        WHERE users_user_id = :uid
    """), {"uid": user_id}).fetchone()

    if not teacher_row:
        return jsonify([])

    rows = db.session.execute(db.text("""
        SELECT 
            q.quiz_id,
            q.title,
            q.start_time,
            q.end_time,
            q.exam_type,
            q.percentage_weight,
            q.class_id,
            c.class_name,
            c.grade_level,
            s.subject_id,
            s.subject_name,
            (SELECT COUNT(*) FROM quiz_questions qq WHERE qq.quiz_id = q.quiz_id) AS question_count
        FROM quizzes q
        JOIN classes c ON c.class_id = q.class_id
        JOIN subjects s ON s.subject_id = q.subject_id
        WHERE q.teacher_id = :tid
        ORDER BY q.start_time DESC
    """), {"tid": teacher_row.teacher_id}).fetchall()

    def serialize(row):
        return {
            "quiz_id": row.quiz_id,
            "title": row.title,
            "start_time": row.start_time.isoformat() if row.start_time else None,
            "end_time": row.end_time.isoformat() if row.end_time else None,
            "exam_type": row.exam_type,
            "percentage_weight": row.percentage_weight,
            "class_id": row.class_id,
            "class_name": row.class_name,
            "grade_level": row.grade_level,
            "subject_id": row.subject_id,
            "subject_name": row.subject_name,
            "question_count": row.question_count or 0,
        }

    return jsonify([serialize(r) for r in rows])


@app.route("/teacher/tests/<int:quiz_id>", methods=["GET", "PUT"])
def teacher_test_detail(quiz_id):
    if not is_logged_in() or session.get("role_id") != 2:
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    teacher_row = db.session.execute(db.text("""
        SELECT teacher_id, subject_id
        FROM teachers
        WHERE users_user_id = :uid
    """), {"uid": user_id}).fetchone()

    if not teacher_row:
        return jsonify({"ok": False, "error": "Teacher profile not found."}), 404

    quiz_row = db.session.execute(db.text("""
        SELECT quiz_id, title, class_id, subject_id, exam_type, percentage_weight, start_time, end_time
        FROM quizzes
        WHERE quiz_id = :qid AND teacher_id = :tid
    """), {"qid": quiz_id, "tid": teacher_row.teacher_id}).fetchone()

    if not quiz_row:
        return jsonify({"ok": False, "error": "Quiz not found."}), 404

    if request.method == "GET":
        questions = db.session.execute(db.text("""
            SELECT question_id, question_text, option_a, option_b, option_c, option_d, correct_option
            FROM quiz_questions
            WHERE quiz_id = :qid
            ORDER BY question_id
        """), {"qid": quiz_id}).fetchall()

        duration_minutes = int((quiz_row.end_time - quiz_row.start_time).total_seconds() // 60) if quiz_row.end_time and quiz_row.start_time else None

        return jsonify({
            "ok": True,
            "quiz": {
                "quiz_id": quiz_row.quiz_id,
                "title": quiz_row.title,
                "class_id": quiz_row.class_id,
                "subject_id": quiz_row.subject_id,
                "exam_type": quiz_row.exam_type,
                "percentage_weight": quiz_row.percentage_weight,
                "testDate": quiz_row.start_time.date().isoformat() if quiz_row.start_time else None,
                "testTime": quiz_row.start_time.strftime("%H:%M") if quiz_row.start_time else None,
                "duration": duration_minutes,
                "questions": [
                    {
                        "question_id": q.question_id,
                        "question": q.question_text,
                        "option_a": q.option_a,
                        "option_b": q.option_b,
                        "option_c": q.option_c,
                        "option_d": q.option_d,
                        "correct_option": q.correct_option,
                    }
                    for q in questions
                ]
            }
        })

    # PUT (update)
    data = request.get_json(silent=True) or {}

    required = {
        "title": data.get("title", "").strip(),
        "subject_id": data.get("subject_id"),
        "class_id": data.get("class_id"),
        "duration": data.get("duration"),
        "testDate": data.get("testDate"),
        "testTime": data.get("testTime"),
    }

    missing = [k for k, v in required.items() if not v and v != 0]
    if missing:
        return jsonify({"ok": False, "error": f"Missing fields: {', '.join(missing)}"}), 400

    try:
        title = required["title"]
        subject_id = int(required["subject_id"])
        class_id = int(required["class_id"])
        duration = int(required["duration"])
        test_date = required["testDate"]
        test_time = required["testTime"]
        start_dt = datetime.strptime(f"{test_date} {test_time}", "%Y-%m-%d %H:%M")
        end_dt = start_dt + timedelta(minutes=duration)
    except Exception:
        return jsonify({"ok": False, "error": "Invalid field types."}), 400

    questions = data.get("questions") or []
    if not questions:
        return jsonify({"ok": False, "error": "At least one question is required."}), 400

    exam_type = data.get("exam_type") or quiz_row.exam_type or "Quiz"
    percentage_weight = data.get("percentage_weight") or quiz_row.percentage_weight or 0

    try:
        db.session.execute(db.text("""
            UPDATE quizzes
            SET title = :title,
                class_id = :class_id,
                subject_id = :subject_id,
                exam_type = :exam_type,
                percentage_weight = :percentage_weight,
                start_time = :start_time,
                end_time = :end_time
            WHERE quiz_id = :qid AND teacher_id = :tid
        """), {
            "title": title,
            "class_id": class_id,
            "subject_id": subject_id,
            "exam_type": exam_type,
            "percentage_weight": percentage_weight,
            "start_time": start_dt,
            "end_time": end_dt,
            "qid": quiz_id,
            "tid": teacher_row.teacher_id
        })

        db.session.execute(db.text("DELETE FROM quiz_questions WHERE quiz_id = :qid"), {"qid": quiz_id})

        for q in questions:
            db.session.execute(db.text("""
                INSERT INTO quiz_questions 
                    (quiz_id, question_text, option_a, option_b, option_c, option_d, correct_option)
                VALUES 
                    (:quiz_id, :question_text, :option_a, :option_b, :option_c, :option_d, :correct_option)
            """), {
                "quiz_id": quiz_id,
                "question_text": q.get("question", "").strip(),
                "option_a": q.get("option_a", ""),
                "option_b": q.get("option_b", ""),
                "option_c": q.get("option_c", ""),
                "option_d": q.get("option_d", ""),
                "correct_option": q.get("correct_option", "")
            })

        db.session.commit()
        log_activity(user_id, f"Updated quiz '{title}'")

        return jsonify({"ok": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500


@app.route("/student")
def student_dashboard():
    if not is_logged_in() or session.get("role_id") != 3:
        return redirect(url_for("login"))
    user_id = session.get("user_id")

    now = datetime.now()

    student_row = db.session.execute(db.text("""
        SELECT s.student_id, s.class_id
        FROM students s
        WHERE s.users_user_id = :uid
    """), {"uid": user_id}).fetchone()

    available_quizzes = []

    if student_row and student_row.class_id:
        rows = db.session.execute(db.text("""
            SELECT 
                q.quiz_id,
                q.title,
                q.start_time,
                q.end_time,
                q.exam_type,
                q.percentage_weight,
                q.class_id,
                c.class_name,
                c.grade_level,
                q.subject_id,
                s.subject_name,
                q.teacher_id,
                (SELECT COUNT(*) FROM quiz_questions qq WHERE qq.quiz_id = q.quiz_id) AS question_count,
                -- Has this student already submitted this quiz?
                (SELECT COUNT(*) FROM quiz_results qr WHERE qr.quiz_id = q.quiz_id AND qr.student_id = :sid) AS taken_count
            FROM quizzes q
            JOIN classes c ON c.class_id = q.class_id
            JOIN subjects s ON s.subject_id = q.subject_id
            WHERE q.class_id = :cid AND q.is_active = 1
            ORDER BY q.start_time DESC
        """), {"cid": student_row.class_id, "sid": student_row.student_id}).fetchall()

        for r in rows:
            duration_minutes = None
            if r.start_time and r.end_time:
                duration_minutes = int((r.end_time - r.start_time).total_seconds() // 60)

            status = "available"
            if r.start_time and now < r.start_time:
                status = "upcoming"
            if r.end_time and now > r.end_time:
                status = "closed"

            # If the student already submitted this quiz, mark as completed
            if getattr(r, 'taken_count', 0) and int(r.taken_count) > 0:
                status = 'completed'

            exam_type = (r.exam_type or "Quiz").strip()
            exam_key = exam_type.lower()

            available_quizzes.append({
                "id": r.quiz_id,
                "title": r.title,
                "subject": r.subject_name,
                "class_name": r.class_name,
                "grade_level": r.grade_level,
                "type": exam_key,
                "display_type": exam_type,
                "question_count": r.question_count or 0,
                "start_time": r.start_time.isoformat() if r.start_time else None,
                "end_time": r.end_time.isoformat() if r.end_time else None,
                "duration": duration_minutes or 30,
                "status": status,
                "taken": int(r.taken_count) if getattr(r, 'taken_count', None) is not None else 0,
                "percentage_weight": r.percentage_weight or 0,
            })

    return render_template("student/student_dashboard.html", available_quizzes=available_quizzes)


@app.route("/student/quiz")
def student_quiz():
    if not is_logged_in() or session.get("role_id") != 3:
        return redirect(url_for("login"))
    quiz_id = request.args.get("id", type=int)

    user_id = session.get("user_id")
    student_row = db.session.execute(db.text("""
        SELECT s.student_id, s.class_id
        FROM students s
        WHERE s.users_user_id = :uid
    """), {"uid": user_id}).fetchone()

    if not student_row:
        flash("Student profile not found.", "danger")
        return redirect(url_for("student_dashboard"))

    quiz_data = None

    if quiz_id:
        quiz_row = db.session.execute(db.text("""
            SELECT 
                q.quiz_id,
                q.title,
                q.class_id,
                q.subject_id,
                q.teacher_id,
                q.exam_type,
                q.percentage_weight,
                q.start_time,
                q.end_time,
                c.class_name,
                c.grade_level,
                s.subject_name
            FROM quizzes q
            JOIN classes c ON c.class_id = q.class_id
            JOIN subjects s ON s.subject_id = q.subject_id
            WHERE q.quiz_id = :qid AND q.is_active = 1
        """), {"qid": quiz_id}).fetchone()

        if quiz_row and quiz_row.class_id == student_row.class_id:
            # Prevent reopening a quiz the student already submitted
            taken = db.session.execute(db.text("SELECT 1 FROM quiz_results WHERE quiz_id = :qid AND student_id = :sid LIMIT 1"), {"qid": quiz_id, "sid": student_row.student_id}).fetchone()
            if taken:
                flash("You have already submitted this quiz.", "warning")
                return redirect(url_for("student_dashboard"))

            now = datetime.now()
            if quiz_row.start_time and now < quiz_row.start_time:
                flash("This quiz is not open yet.", "warning")
                return redirect(url_for("student_dashboard"))
            if quiz_row.end_time and now > quiz_row.end_time:
                flash("This quiz is closed.", "danger")
                return redirect(url_for("student_dashboard"))
            questions = db.session.execute(db.text("""
                SELECT question_id, question_text, option_a, option_b, option_c, option_d, correct_option
                FROM quiz_questions
                WHERE quiz_id = :qid
                ORDER BY question_id
            """), {"qid": quiz_id}).fetchall()

            if not questions:
                flash("This quiz has no questions configured yet.", "warning")
                return redirect(url_for("student_dashboard"))

            duration_minutes = 30
            if quiz_row.start_time and quiz_row.end_time:
                duration_minutes = int((quiz_row.end_time - quiz_row.start_time).total_seconds() // 60)

            def option_index(letter: str) -> int:
                mapping = {"A": 0, "B": 1, "C": 2, "D": 3}
                return mapping.get((letter or "").upper(), 0)

            quiz_data = {
                "info": {
                    "id": quiz_row.quiz_id,
                    "title": quiz_row.title,
                    "subject": quiz_row.subject_name,
                    "timeLimit": duration_minutes,
                    "type": quiz_row.exam_type or "exam",
                    "instructions": [
                        "Read each question carefully before selecting your answer",
                        "You can navigate between questions using the Previous and Next buttons",
                        "Your answers will be auto-saved every 30 seconds",
                        "Make sure to submit your quiz before the timer runs out",
                        "Once submitted, you cannot change your answers"
                    ]
                },
                "questions": [
                    {
                        "id": q.question_id,
                        "text": q.question_text,
                        "type": "mcq",
                        "options": [q.option_a, q.option_b, q.option_c, q.option_d],
                        "correctAnswer": option_index(q.correct_option),
                    }
                    for q in questions
                ]
            }

    return render_template("student/quiz.html", quiz_data=quiz_data)


@app.route("/student/quizzes/<int:quiz_id>/submit", methods=["POST"])
def student_submit_quiz(quiz_id):
    if not is_logged_in() or session.get("role_id") != 3:
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    student_row = db.session.execute(db.text("""
        SELECT s.student_id, s.class_id
        FROM students s
        WHERE s.users_user_id = :uid
    """), {"uid": user_id}).fetchone()

    if not student_row:
        return jsonify({"ok": False, "error": "Student profile not found."}), 404

    quiz_row = db.session.execute(db.text("""
        SELECT quiz_id, class_id, subject_id, teacher_id, start_time, end_time
        FROM quizzes
        WHERE quiz_id = :qid AND is_active = 1
    """), {"qid": quiz_id}).fetchone()

    if not quiz_row or quiz_row.class_id != student_row.class_id:
        return jsonify({"ok": False, "error": "Quiz not available."}), 404

    # Prevent duplicate submissions (use existing quiz_results table)
    exists = db.session.execute(db.text("SELECT 1 FROM quiz_results WHERE quiz_id = :qid AND student_id = :sid LIMIT 1"), {"qid": quiz_id, "sid": student_row.student_id}).fetchone()
    if exists:
        return jsonify({"ok": False, "error": "Quiz already submitted."}), 400

    now = datetime.now()
    if quiz_row.start_time and now < quiz_row.start_time:
        return jsonify({"ok": False, "error": "Quiz not open yet."}), 403
    if quiz_row.end_time and now > quiz_row.end_time:
        return jsonify({"ok": False, "error": "Quiz has closed."}), 403

    data = request.get_json(silent=True) or {}
    answers = data.get("answers") or []

    if not answers:
        return jsonify({"ok": False, "error": "No answers submitted."}), 400

    answer_map = {int(item.get("question_id")): (item.get("selected_option") or "").upper() for item in answers if item.get("question_id")}

    if not answer_map:
        return jsonify({"ok": False, "error": "Invalid answers payload."}), 400

    questions = db.session.execute(db.text("""
        SELECT question_id, correct_option
        FROM quiz_questions
        WHERE quiz_id = :qid
    """), {"qid": quiz_id}).fetchall()

    if not questions:
        return jsonify({"ok": False, "error": "Quiz has no questions."}), 400

    mapping = {"A": 0, "B": 1, "C": 2, "D": 3}
    total = len(questions)
    correct = 0

    for q in questions:
        sel_letter = answer_map.get(q.question_id)
        if not sel_letter:
            continue
        if mapping.get(sel_letter, -1) == mapping.get((q.correct_option or "").upper(), -2):
            correct += 1

    score_percent = round((correct / total) * 100, 2)

    def letter_grade(score: float) -> str:
        if score >= 90:
            return "A"
        if score >= 80:
            return "B"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"

    grade_letter = letter_grade(score_percent)

    try:
        db.session.execute(db.text("""
            INSERT INTO test_results (test_date, student_id, class_id, subject_id, teacher_id, quiz_score)
            VALUES (:test_date, :student_id, :class_id, :subject_id, :teacher_id, :quiz_score)
        """), {
            "test_date": datetime.utcnow(),
            "student_id": student_row.student_id,
            "class_id": quiz_row.class_id,
            "subject_id": quiz_row.subject_id,
            "teacher_id": quiz_row.teacher_id,
            "quiz_score": score_percent
        })
        db.session.commit()
        # Also mark this quiz as submitted for this student (record in existing quiz_results table)
        try:
            db.session.execute(db.text("""
                INSERT INTO quiz_results (quiz_id, student_id, score, submitted_at)
                VALUES (:qid, :sid, :score, :time)
            """), {
                "qid": quiz_id,
                "sid": student_row.student_id,
                "score": score_percent,
                "time": datetime.utcnow()
            })
            db.session.commit()
        except Exception:
            db.session.rollback()

        log_activity(user_id, f"Submitted quiz {quiz_id} with score {score_percent}%")
    except Exception as e:
        db.session.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({
        "ok": True,
        "score": score_percent,
        "correct": correct,
        "total": total,
        "grade": grade_letter
    })


@app.route("/student/report")
def student_report():
    if not is_logged_in() or session.get("role_id") != 3:
        return redirect(url_for("login"))
    return render_template("student/report.html")


@app.route("/student/report/data")
def student_report_data():
    if not is_logged_in() or session.get("role_id") != 3:
        return jsonify({"ok": False, "error": "Unauthorized"}), 401

    user_id = session.get("user_id")
    student_row = db.session.execute(db.text("""
        SELECT student_id
        FROM students
        WHERE users_user_id = :uid
    """), {"uid": user_id}).fetchone()

    if not student_row:
        return jsonify({"ok": False, "error": "Student profile not found."}), 404

    rows = db.session.execute(db.text("""
        SELECT
            tr.result_id,
            tr.test_date,
            tr.quiz_score,
            tr.grade,
            sub.subject_name,
            u.full_name AS teacher_name
        FROM test_results tr
        JOIN subjects sub ON sub.subject_id = tr.subject_id
        JOIN teachers t ON t.teacher_id = tr.teacher_id
        JOIN users u ON u.user_id = t.users_user_id
        WHERE tr.student_id = :sid
        ORDER BY tr.test_date DESC
    """), {"sid": student_row.student_id}).fetchall()

    def letter(score: float) -> str:
        if score is None:
            return "-"
        try:
            s = float(score)
        except Exception:
            return str(score)
        if s >= 90:
            return "A"
        if s >= 80:
            return "B"
        if s >= 70:
            return "C"
        if s >= 60:
            return "D"
        return "F"

    data_rows = []
    scores = []
    labels = []

    for r in rows:
        grade_val = r.grade if r.grade is not None else letter(r.quiz_score)
        data_rows.append({
            "id": r.result_id,
            "title": r.subject_name,
            "subject": r.subject_name,
            "teacher": r.teacher_name,
            "date": r.test_date.isoformat() if r.test_date else None,
            "score": float(r.quiz_score) if r.quiz_score is not None else None,
            "grade": grade_val,
            "status": "Completed",
        })
        if r.test_date and r.quiz_score is not None:
            labels.append(r.test_date.strftime("%b %d"))
            try:
                scores.append(float(r.quiz_score))
            except Exception:
                scores.append(None)

    total_completed = len(data_rows)
    numeric_scores = [s for s in scores if s is not None]
    avg_score = round(sum(numeric_scores) / len(numeric_scores), 2) if numeric_scores else None
    top_score = max(numeric_scores) if numeric_scores else None

    summary = {
        "completed": total_completed,
        "avg_score": avg_score,
        "pending": 0,
        "top": top_score,
    }

    return jsonify({
        "ok": True,
        "summary": summary,
        "labels": labels[::-1],
        "scores": scores[::-1],
        "results": data_rows,
    })

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
