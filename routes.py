import json
import logging
from flask import render_template, request, redirect, url_for, flash, jsonify, session
from app import app, db
from models import FieldMapping, SplunkSettings, QueryHistory
from utils import (
    convert_sigma_to_spl,
    execute_splunk_query,
    test_splunk_connection,
    save_query_results,
    suggest_field_mappings
)

@app.route('/')
def home():
    """Home page with navigation buttons"""
    return render_template('home.html')

@app.route('/query', methods=['GET', 'POST'])
def query():
    """Page to input Sigma rules, convert to SPL, and run queries"""
    error = None
    sigma_rule = ""
    splunk_query = ""
    results = None
    time_range = "Last 30 days"
    suggestions = {}
    
    # Get the latest field mapping
    field_mapping = FieldMapping.get_latest_mapping()
    if not field_mapping:
        error = "Field mapping not found. Please configure field mappings first."
        return render_template(
            'query.html', 
            error=error,
            sigma_rule=sigma_rule,
            splunk_query=splunk_query,
            results=results,
            time_range=time_range
        )
    
    if request.method == 'POST':
        action = request.form.get('action', '')
        
        if action == 'convert':
            # Get form data
            sigma_rule = request.form.get('sigma_rule', '')
            
            if not sigma_rule:
                error = "Please provide a Sigma rule"
            else:
                # Convert Sigma to SPL
                splunk_query, error = convert_sigma_to_spl(sigma_rule, field_mapping.mapping_data)
                
                # Generate suggestions for unmapped fields
                if not error:
                    suggestions = suggest_field_mappings(field_mapping.mapping_data, sigma_rule)
                
        elif action == 'execute':
            # Get form data
            sigma_rule = request.form.get('sigma_rule', '')
            splunk_query = request.form.get('splunk_query', '')
            time_range = request.form.get('time_range', 'Last 30 days')
            
            if not splunk_query:
                error = "Please provide a Splunk query"
            else:
                # Execute the Splunk query
                results, error = execute_splunk_query(splunk_query, time_range)
                
                # Save the query results to database
                if results is not None:
                    query_history = save_query_results(
                        sigma_rule=sigma_rule,
                        splunk_query=splunk_query,
                        results=results,
                        time_range=time_range
                    )
                    if query_history:
                        flash("Query results saved successfully", "success")
                    else:
                        flash("Failed to save query results", "danger")
                else:
                    # Save the failed query
                    save_query_results(
                        sigma_rule=sigma_rule,
                        splunk_query=splunk_query,
                        results=None,
                        time_range=time_range,
                        status="Failed",
                        error_message=error
                    )
    
    return render_template(
        'query.html', 
        error=error,
        sigma_rule=sigma_rule,
        splunk_query=splunk_query,
        results=results,
        time_range=time_range,
        suggestions=suggestions
    )

@app.route('/results')
def results():
    """Page to view past query results"""
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Get query history from database with pagination
    query_history = QueryHistory.query.order_by(
        QueryHistory.execution_time.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('results.html', query_history=query_history)

@app.route('/results/<int:query_id>')
def view_result(query_id):
    """View detailed results for a specific query"""
    query = QueryHistory.query.get_or_404(query_id)
    return render_template('results.html', query=query)

@app.route('/mapping', methods=['GET', 'POST'])
def mapping():
    """Page to view and edit field mappings"""
    error = None
    success = None
    
    # Get the latest field mapping
    field_mapping = FieldMapping.get_latest_mapping()
    if not field_mapping:
        field_mapping = FieldMapping(mapping_data={})
    
    if request.method == 'POST':
        try:
            # Get mapping data from form
            mapping_data = {}
            form_data = request.form
            
            # Process form data to extract field mappings
            for key in form_data:
                if key.startswith('sigma_field_'):
                    index = key.replace('sigma_field_', '')
                    sigma_field = form_data.get(f'sigma_field_{index}', '').strip()
                    splunk_field = form_data.get(f'splunk_field_{index}', '').strip()
                    
                    if sigma_field and splunk_field:
                        mapping_data[sigma_field] = splunk_field
            
            # Save the new mapping
            new_mapping = FieldMapping(mapping_data=mapping_data)
            db.session.add(new_mapping)
            db.session.commit()
            
            success = "Field mappings updated successfully"
            field_mapping = new_mapping
            
        except Exception as e:
            db.session.rollback()
            error = f"Error updating field mappings: {str(e)}"
            logging.error(error)
    
    return render_template(
        'mapping.html', 
        field_mapping=field_mapping,
        error=error,
        success=success
    )

@app.route('/settings', methods=['GET', 'POST'])
def settings():
    """Page to view and edit Splunk connection settings"""
    error = None
    success = None
    
    # Get the current Splunk settings
    splunk_settings = SplunkSettings.get_settings()
    if not splunk_settings:
        splunk_settings = SplunkSettings(
            host="",
            port=8089,
            username="",
            password=""
        )
    
    if request.method == 'POST':
        try:
            # Get settings from form
            host = request.form.get('host', '').strip()
            port = int(request.form.get('port', 8089))
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            # Use existing password if not provided
            if not password and splunk_settings.id:
                password = splunk_settings.password
            
            # Validate settings
            if not host:
                error = "Host is required"
            elif not username:
                error = "Username is required"
            elif not password:
                error = "Password is required"
            else:
                # Save the new settings
                new_settings = SplunkSettings(
                    host=host,
                    port=port,
                    username=username,
                    password=password
                )
                db.session.add(new_settings)
                db.session.commit()
                
                success = "Splunk settings updated successfully"
                splunk_settings = new_settings
                
        except Exception as e:
            db.session.rollback()
            error = f"Error updating Splunk settings: {str(e)}"
            logging.error(error)
    
    return render_template(
        'settings.html', 
        splunk_settings=splunk_settings,
        error=error,
        success=success
    )

@app.route('/test-connection', methods=['POST'])
def test_connection():
    """API endpoint to test Splunk connection"""
    try:
        # Get settings from form or database
        if request.form:
            host = request.form.get('host', '').strip()
            port = int(request.form.get('port', 8089))
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            
            if not password:
                # Get existing password if not provided
                settings = SplunkSettings.get_settings()
                if settings:
                    password = settings.password
        else:
            # Get settings from database
            settings = SplunkSettings.get_settings()
            if not settings:
                return jsonify({
                    'success': False,
                    'message': 'Splunk settings not found'
                })
            
            host = settings.host
            port = settings.port
            username = settings.username
            password = settings.password
        
        # Test the connection
        success, message = test_splunk_connection(host, port, username, password)
        
        return jsonify({
            'success': success,
            'message': message
        })
        
    except Exception as e:
        error = f"Error testing Splunk connection: {str(e)}"
        logging.error(error)
        
        return jsonify({
            'success': False,
            'message': error
        })

@app.errorhandler(404)
def page_not_found(e):
    return render_template('base.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_server_error(e):
    return render_template('base.html', error="Internal server error"), 500
