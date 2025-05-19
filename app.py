import os
import logging

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix


# Configure logging
logging.basicConfig(level=logging.DEBUG)

class Base(DeclarativeBase):
    pass


db = SQLAlchemy(model_class=Base)
# create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "threat_hunting_secret_key")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # needed for url_for to generate with https

# configure the database connection
database_url = os.environ.get("DATABASE_URL")
if database_url and database_url.startswith("postgres://"):
    # Handle old style connection string
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# initialize the app with the extension
db.init_app(app)

with app.app_context():
    # Import models to ensure tables are created
    import models  # noqa: F401
    
    # Try to create tables safely
    try:
        db.create_all()
        logging.info("Database tables created successfully")
        
        # Initialize default data if needed
        from models import FieldMapping, SplunkSettings
        
        # Add default field mapping if it doesn't exist
        try:
            mapping_count = FieldMapping.query.count()
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
                logging.info("Default field mapping created")
        except Exception as e:
            db.session.rollback()
            logging.warning(f"Error checking or creating field mappings: {e}")
        
        # Add default Splunk settings if they don't exist
        try:
            settings_count = SplunkSettings.query.count()
            if settings_count == 0:
                default_settings = SplunkSettings(
                    host="splunk-server.example.com",
                    port=8089,
                    username="admin",
                    password="changeme"
                )
                db.session.add(default_settings)
                db.session.commit()
                logging.info("Default Splunk settings created")
        except Exception as e:
            db.session.rollback()
            logging.warning(f"Error checking or creating Splunk settings: {e}")
    
    except Exception as e:
        logging.error(f"Error setting up database: {e}")
