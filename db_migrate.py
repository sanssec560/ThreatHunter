import logging
from app import app, db
from models import SigmaRule, Hunt, QueryHistory

def migrate_database():
    """
    Run database migrations to update schema based on models
    """
    try:
        with app.app_context():
            # Create the tables if they don't exist
            db.create_all()
            
            # Add hunt_id column to query_history if it doesn't exist
            try:
                db.session.execute('ALTER TABLE query_history ADD COLUMN IF NOT EXISTS hunt_id INTEGER REFERENCES hunts(id)')
                db.session.commit()
                print("Successfully migrated database schema")
            except Exception as e:
                db.session.rollback()
                print(f"Error adding hunt_id column: {str(e)}")
                # Try creating just the tables that might be missing
                try:
                    db.metadata.create_all(db.engine, 
                                          tables=[Hunt.__table__, SigmaRule.__table__],
                                          checkfirst=True)
                    db.session.commit()
                    print("Created new tables")
                except Exception as e:
                    print(f"Error creating tables: {str(e)}")
    except Exception as e:
        print(f"Migration error: {str(e)}")

if __name__ == "__main__":
    migrate_database()