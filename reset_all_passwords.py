
from app import app, db
from models import User
from werkzeug.security import generate_password_hash


def reset_all_passwords():
    with app.app_context():
        users = User.query.all()
        fixed_count = 0

        for user in users:
            first = (user.full_name.split()[0]).lower()

            new_plain = f"{first}123@@"
            new_hash = generate_password_hash(new_plain)

            print(f"[UPDATE] {user.username} → {new_plain}")

            user.password = new_hash
            user.force_password_change = 1
            fixed_count += 1

        db.session.commit()

        print("--------------------------------------------------")
        print(f"Completed! Updated {fixed_count} user passwords.")
        print("--------------------------------------------------")


# -------------------------------------------------------------
# Script will only run manually.
# Won't run when imported by Flask.
# -------------------------------------------------------------
if __name__ == "__main__":
    reset_all_passwords()
