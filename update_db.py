from app import app, db
from sqlalchemy import text

with app.app_context():
    try:
        # Add lat/lon/country to scan_result
        try:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE scan_result ADD COLUMN lat FLOAT"))
                conn.execute(text("ALTER TABLE scan_result ADD COLUMN lon FLOAT"))
                conn.execute(text("ALTER TABLE scan_result ADD COLUMN country TEXT"))
            print("Added geo columns to scan_result")
        except Exception as e:
            print(f"Geo columns might already exist: {e}")

        # Add api_key to user
        try:
             with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE user ADD COLUMN api_key TEXT"))
             print("Added api_key to user")
        except Exception as e:
            print(f"api_key might already exist: {e}")

        # Create UserRule table
        db.create_all()
        print("Created new tables (UserRule)")
        
    except Exception as e:
        print(f"Migration error: {e}")
