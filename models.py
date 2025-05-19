import json
from datetime import datetime
from app import db
from sqlalchemy.types import JSON, Text
from sqlalchemy.exc import SQLAlchemyError
import logging
from sqlalchemy.orm import relationship

class FieldMapping(db.Model):
    __tablename__ = 'field_mappings'
    
    id = db.Column(db.Integer, primary_key=True)
    mapping_data = db.Column(JSON, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @classmethod
    def get_latest_mapping(cls):
        try:
            return cls.query.order_by(cls.updated_at.desc()).first()
        except SQLAlchemyError as e:
            logging.error(f"Database error retrieving latest mapping: {e}")
            return None

    def to_dict(self):
        return {
            'id': self.id,
            'mapping_data': self.mapping_data,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class SplunkSettings(db.Model):
    __tablename__ = 'splunk_settings'
    
    id = db.Column(db.Integer, primary_key=True)
    host = db.Column(db.String(255), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    username = db.Column(db.String(255), nullable=False)
    password = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    @classmethod
    def get_settings(cls):
        try:
            return cls.query.order_by(cls.updated_at.desc()).first()
        except SQLAlchemyError as e:
            logging.error(f"Database error retrieving Splunk settings: {e}")
            return None

    def to_dict(self):
        return {
            'id': self.id,
            'host': self.host,
            'port': self.port,
            'username': self.username,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }


class Hunt(db.Model):
    """Model for a collection of queries executed as a hunt session"""
    __tablename__ = 'hunts'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship with queries that belong to this hunt
    queries = relationship("QueryHistory", back_populates="hunt")
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'query_count': len(self.queries)
        }


class SigmaRule(db.Model):
    """Model for storing Sigma rules library"""
    __tablename__ = 'sigma_rules'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    rule_id = db.Column(db.String(255))
    content = db.Column(Text, nullable=False)
    category = db.Column(db.String(100))
    product = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'rule_id': self.rule_id,
            'content': self.content,
            'category': self.category,
            'product': self.product,
            'created_at': self.created_at.isoformat()
        }


class QueryHistory(db.Model):
    __tablename__ = 'query_history'
    
    id = db.Column(db.Integer, primary_key=True)
    sigma_rule = db.Column(Text, nullable=False)
    splunk_query = db.Column(Text, nullable=False)
    results = db.Column(JSON)
    time_range = db.Column(db.String(50), nullable=False)
    execution_time = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(50), default="Success")  # Success, Failed, etc.
    error_message = db.Column(db.Text)
    
    # Foreign key to link to a hunt (nullable - can be a standalone query)
    hunt_id = db.Column(db.Integer, db.ForeignKey('hunts.id'), nullable=True)
    
    # Relationship back to the hunt
    hunt = relationship("Hunt", back_populates="queries")
    
    def to_dict(self):
        return {
            'id': self.id,
            'sigma_rule': self.sigma_rule,
            'splunk_query': self.splunk_query,
            'results': self.results,
            'time_range': self.time_range,
            'execution_time': self.execution_time.isoformat(),
            'status': self.status,
            'error_message': self.error_message,
            'hunt_id': self.hunt_id
        }
