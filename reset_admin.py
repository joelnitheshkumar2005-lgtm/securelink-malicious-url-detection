from app import app, db, User
from werkzeug.security import generate_password_hash

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if admin:
        print(f"Found existing admin. Resetting password...")
        admin.password = generate_password_hash('admin123', method='pbkdf2:sha256')
        db.session.commit()
        print("SUCCESS: Password reset to 'admin123'")
    else:
        print("Admin not found. Creating...")
        new_admin = User(username='admin', email='admin@securelink.com', password=generate_password_hash('admin123', method='pbkdf2:sha256'))
        db.session.add(new_admin)
        db.session.commit()
        print("SUCCESS: Created admin user with password 'admin123'")
