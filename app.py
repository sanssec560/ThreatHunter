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
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", 
    "postgresql://hunter:hunter123@localhost:5432/threathunter"
)
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
    
    db.create_all()
    
    # Initialize default data if needed
    from models import FieldMapping, SplunkSettings
    
    # Add default field mapping if it doesn't exist
    if FieldMapping.query.count() == 0:
        default_mapping = FieldMapping(
            mapping_data={
                "user.name": "user", 
                "process.name": "proc"
            }
        )
        db.session.add(default_mapping)
        db.session.commit()
        logging.info("Default field mapping created")
    
    # Add default Splunk settings if they don't exist
    if SplunkSettings.query.count() == 0:
        default_settings = SplunkSettings(
            host="192.168.128.224",
            port=8089,
            username="salah",
            password="asd@12345"
        )
        db.session.add(default_settings)
        db.session.commit()
        logging.info("Default Splunk settings created")
