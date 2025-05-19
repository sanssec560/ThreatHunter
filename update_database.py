"""
Script to update the database schema
"""
import os
import logging
from app import app, db
from sqlalchemy import text

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def create_tables():
    """Create or update database tables"""
    with app.app_context():
        try:
            # Create all tables based on models
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Check if hunt_id column exists in query_history
            try:
                db.session.execute(text("SELECT hunt_id FROM query_history LIMIT 1"))
                logger.info("hunt_id column already exists")
            except Exception:
                # Add the hunt_id column if it doesn't exist
                try:
                    db.session.execute(text("ALTER TABLE query_history ADD COLUMN hunt_id INTEGER"))
                    db.session.commit()
                    logger.info("Added hunt_id column to query_history table")
                except Exception as e:
                    db.session.rollback()
                    logger.error(f"Error adding hunt_id column: {e}")
            
            # Initialize default data if needed
            from models import FieldMapping, SplunkSettings
            
            # Add default field mapping if it doesn't exist
            mapping_count = db.session.query(FieldMapping).count()
            if mapping_count == 0:
                default_mapping = FieldMapping(
                    mapping_data={
                        "Image": "NewProcessName",
                        "ParentImage": "ParentProcessName",
                        "CommandLine": "CommandLine",
                        "User": "User",
                        "IntegrityLevel": "IntegrityLevel"
                    }
                )
                db.session.add(default_mapping)
                db.session.commit()
                logger.info("Default field mapping created")
            
            # Add default Splunk settings if they don't exist
            settings_count = db.session.query(SplunkSettings).count()
            if settings_count == 0:
                default_settings = SplunkSettings(
                    host="splunk-server.example.com",
                    port=8089,
                    username="admin",
                    password="changeme"
                )
                db.session.add(default_settings)
                db.session.commit()
                logger.info("Default Splunk settings created")
                
        except Exception as e:
            logger.error(f"Error updating database: {e}")

if __name__ == "__main__":
    create_tables()