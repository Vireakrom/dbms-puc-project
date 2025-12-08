# Technology Stack

## Backend
- **Flask (Python)**: Handles routing, session/auth flows, form processing, JSON endpoints (`app.py`).
- **Werkzeug Security**: Password hashing and verification for user auth.
- **Standard Library**: `datetime`, `csv`, `io`, `re`, `os` for validation, exports, and configuration helpers.

## Data Layer
- **Flask-SQLAlchemy / SQLAlchemy**: ORM models for roles, users, students, teachers, classes, subjects; query/session management (`models.py`).
- **MySQL**: Primary relational database. Connection via `mysql+mysqlconnector` DSN (env-driven) and direct `mysql.connector` helper (`db.py`).

## Templating & Views
- **Jinja2**: Server-rendered HTML templates for admin, teacher, and student flows (`templates/`).

## Frontend UI
- **Bootstrap 5 (CDN)**: Layout grid, components, and utilities (base templates under `templates/*/`).
- **Bootstrap Icons (CDN)**: Icon set for headers and navigation.
- **Custom CSS**: Project-specific styling in `static/css/style.css` plus inline styles in shared templates.
- **Vanilla JavaScript**: Small interactive behaviors (e.g., logout modal in `templates/components/header.html`).

## Configuration
- **Environment-Driven DB Settings**: `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_NAME`, or `DATABASE_URL` override defaults in `models.py`.
- **App Secret Key**: `SECRET_KEY` env var for Flask sessions (falls back to a default).
