"""
Script to reset and set up the database from scratch
This should be used for development only, not in production
"""

import os
import logging
from app import app, db
from sqlalchemy import text, inspect
from models import FieldMapping, SplunkSettings, QueryHistory, Hunt, SigmaRule

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def reset_database():
    """Reset the database and create all tables from scratch"""
    with app.app_context():
        # Drop all tables (but handle errors)
        try:
            db.drop_all()
            logger.info("All tables dropped successfully")
        except Exception as e:
            logger.error(f"Error dropping tables: {e}")
        
        # Create all tables
        try:
            db.create_all()
            logger.info("All tables created successfully")
        except Exception as e:
            logger.error(f"Error creating tables: {e}")
            return
        
        # Verify tables
        try:
            inspector = inspect(db.engine)
            tables = inspector.get_table_names()
            logger.info(f"Created tables: {', '.join(tables)}")
            
            # Verify hunt_id column in query_history
            columns = inspector.get_columns('query_history')
            column_names = [col['name'] for col in columns]
            logger.info(f"Columns in query_history: {', '.join(column_names)}")
            
            if 'hunt_id' not in column_names:
                logger.error("hunt_id not found in query_history")
            else:
                logger.info("hunt_id column found in query_history")
        except Exception as e:
            logger.error(f"Error inspecting database: {e}")
            
        # Add default field mapping
        try:
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
        except Exception as e:
            logger.error(f"Error creating default field mapping: {e}")
            
        # Add default Splunk settings
        try:
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
            logger.error(f"Error creating default Splunk settings: {e}")

if __name__ == "__main__":
    reset_database()