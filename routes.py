import json
import logging
from datetime import datetime
from flask import render_template, request, redirect, url_for, flash, jsonify, session
from app import app, db
from models import FieldMapping, SplunkSettings, QueryHistory, Hunt, SigmaRule
from utils import (
    convert_sigma_to_spl,
    execute_splunk_query,
    test_splunk_connection,
    save_query_results,
    suggest_field_mappings,
    create_hunt,
    execute_hunt,
    save_sigma_rule,
    download_sigma_rules
)

@app.route('/')
def home():
    """Home page with navigation buttons"""
    # Get counts for dashboard safely
    query_count = 0
    hunt_count = 0
    rule_count = 0
    
    try:
        # Try to get counts but handle missing tables gracefully
        query_count = QueryHistory.query.count() 
    except Exception as e:
        logging.warning(f"Could not fetch query count: {str(e)}")
        
    try:
        hunt_count = Hunt.query.count()
    except Exception as e:
        logging.warning(f"Could not fetch hunt count: {str(e)}")
        
    try:
        rule_count = SigmaRule.query.count()
    except Exception as e:
        logging.warning(f"Could not fetch rule count: {str(e)}")
    
    return render_template('home.html', 
                          query_count=query_count,
                          hunt_count=hunt_count,
                          rule_count=rule_count)

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

@app.route('/hunt', methods=['GET', 'POST'])
def hunt():
    """Page to create and manage automated hunts"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'create_hunt':
            # Create a new hunt
            name = request.form.get('name')
            description = request.form.get('description', '')
            
            if not name:
                flash("Hunt name is required", "danger")
                return redirect(url_for('hunt'))
            
            hunt_obj = create_hunt(name, description)
            if hunt_obj:
                flash(f"Hunt '{name}' created successfully", "success")
                return redirect(url_for('hunt_detail', hunt_id=hunt_obj.id))
            else:
                flash("Failed to create hunt", "danger")
                
        elif action == 'delete_hunt':
            # Delete a hunt
            hunt_id = request.form.get('hunt_id')
            if hunt_id:
                try:
                    hunt_obj = Hunt.query.get(hunt_id)
                    if hunt_obj:
                        db.session.delete(hunt_obj)
                        db.session.commit()
                        flash(f"Hunt '{hunt_obj.name}' deleted successfully", "success")
                    else:
                        flash("Hunt not found", "danger")
                except Exception as e:
                    db.session.rollback()
                    flash(f"Error deleting hunt: {str(e)}", "danger")
            
    # Get all hunts for display
    hunts = Hunt.query.order_by(Hunt.created_at.desc()).all()
    
    return render_template('hunt.html', hunts=hunts)


@app.route('/hunt/<int:hunt_id>', methods=['GET', 'POST'])
def hunt_detail(hunt_id):
    """Page to view and execute a specific hunt"""
    # Get the hunt
    hunt_obj = Hunt.query.get_or_404(hunt_id)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'execute_hunt':
            # Get sigma rules and time range
            sigma_rules = request.form.getlist('sigma_rules')
            time_range = request.form.get('time_range', 'Last 30 days')
            
            if not sigma_rules:
                flash("Please select at least one Sigma rule", "danger")
                return redirect(url_for('hunt_detail', hunt_id=hunt_id))
            
            # Execute the hunt
            results = execute_hunt(hunt_id, sigma_rules, time_range)
            
            # Redirect to the hunt detail page to see results
            flash(f"Hunt execution completed with {len(results)} queries", "success")
            return redirect(url_for('hunt_detail', hunt_id=hunt_id))
            
        elif action == 'add_rule':
            # Add a rule to the hunt's execution list
            rule_id = request.form.get('rule_id')
            if rule_id:
                # We don't actually need to save this association,
                # as rules are selected at execution time
                flash("Rule added to hunt execution list", "success")
                
    # Get the queries associated with this hunt
    queries = QueryHistory.query.filter_by(hunt_id=hunt_id).order_by(QueryHistory.execution_time.desc()).all()
    
    # Get all sigma rules for selection
    sigma_rules = SigmaRule.query.order_by(SigmaRule.title).all()
    
    return render_template(
        'hunt_detail.html', 
        hunt=hunt_obj, 
        queries=queries, 
        sigma_rules=sigma_rules
    )


@app.route('/rules', methods=['GET', 'POST'])
def rules():
    """Page to browse and manage Sigma rules"""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_rule':
            # Add a single rule
            title = request.form.get('title')
            content = request.form.get('content')
            
            if not title or not content:
                flash("Title and content are required", "danger")
            else:
                rule = save_sigma_rule(title, content)
                if rule:
                    flash(f"Rule '{title}' added successfully", "success")
                else:
                    flash("Failed to add rule", "danger")
                    
        elif action == 'delete_rule':
            # Delete a rule
            rule_id = request.form.get('rule_id')
            if rule_id:
                try:
                    rule = SigmaRule.query.get(rule_id)
                    if rule:
                        db.session.delete(rule)
                        db.session.commit()
                        flash(f"Rule '{rule.title}' deleted successfully", "success")
                    else:
                        flash("Rule not found", "danger")
                except Exception as e:
                    db.session.rollback()
                    flash(f"Error deleting rule: {str(e)}", "danger")
                    
        elif action == 'download_rules':
            # Download rules from SigmaHQ
            success, message, count = download_sigma_rules()
            if success:
                flash(message, "success")
            else:
                flash(message, "danger")
                
        return redirect(url_for('rules'))
    
    # Get filters from query parameters
    category = request.args.get('category')
    product = request.args.get('product')
    search = request.args.get('search')
    
    # Build the query
    query = SigmaRule.query
    
    if category:
        query = query.filter(SigmaRule.category == category)
    if product:
        query = query.filter(SigmaRule.product == product)
    if search:
        query = query.filter(SigmaRule.title.ilike(f"%{search}%"))
    
    # Get all sigma rules
    sigma_rules = query.order_by(SigmaRule.title).all()
    
    # Get unique categories and products for filtering
    categories = db.session.query(SigmaRule.category).distinct().all()
    products = db.session.query(SigmaRule.product).distinct().all()
    
    return render_template(
        'rules.html', 
        sigma_rules=sigma_rules,
        categories=[c[0] for c in categories if c[0]],
        products=[p[0] for p in products if p[0]],
        selected_category=category,
        selected_product=product,
        search=search
    )


@app.route('/rules/<int:rule_id>')
def rule_detail(rule_id):
    """Page to view a specific Sigma rule"""
    rule = SigmaRule.query.get_or_404(rule_id)
    
    # Convert to SPL for preview
    field_mapping = FieldMapping.get_latest_mapping()
    mapping_data = field_mapping.mapping_data if field_mapping else None
    splunk_query, error = convert_sigma_to_spl(rule.content, mapping_data)
    
    return render_template(
        'rule_detail.html', 
        rule=rule, 
        splunk_query=splunk_query,
        error=error
    )


@app.route('/rules/execute/<int:rule_id>', methods=['POST'])
def execute_rule(rule_id):
    """Execute a Sigma rule directly"""
    rule = SigmaRule.query.get_or_404(rule_id)
    time_range = request.form.get('time_range', 'Last 30 days')
    
    # Convert and execute
    field_mapping = FieldMapping.get_latest_mapping()
    mapping_data = field_mapping.mapping_data if field_mapping else None
    
    # Convert Sigma to SPL
    splunk_query, error = convert_sigma_to_spl(rule.content, mapping_data)
    
    if error:
        flash(f"Error converting rule: {error}", "danger")
        return redirect(url_for('rule_detail', rule_id=rule_id))
    
    # Execute the query
    results, error = execute_splunk_query(splunk_query, time_range)
    
    if error:
        # Save the failed query
        query_record = save_query_results(
            sigma_rule=rule.content,
            splunk_query=splunk_query,
            results=None,
            time_range=time_range,
            status="Failed",
            error_message=error
        )
        flash(f"Error executing query: {error}", "danger")
    else:
        # Save the successful query
        query_record = save_query_results(
            sigma_rule=rule.content,
            splunk_query=splunk_query,
            results=results,
            time_range=time_range,
            status="Success"
        )
        flash(f"Query executed successfully with {len(results) if results else 0} results", "success")
    
    if query_record:
        return redirect(url_for('view_result', query_id=query_record.id))
    else:
        return redirect(url_for('rule_detail', rule_id=rule_id))


@app.route('/rules/execute-multiple', methods=['POST'])
def execute_multiple_rules():
    """Execute multiple Sigma rules"""
    rule_ids = request.form.getlist('rule_ids')
    time_range = request.form.get('time_range', 'Last 30 days')
    hunt_name = request.form.get('hunt_name', f"Hunt {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    
    if not rule_ids:
        flash("Please select at least one rule", "danger")
        return redirect(url_for('rules'))
    
    # Create a new hunt
    hunt_obj = create_hunt(hunt_name)
    if not hunt_obj:
        flash("Failed to create hunt", "danger")
        return redirect(url_for('rules'))
    
    # Get the rules content
    sigma_rules = []
    for rule_id in rule_ids:
        rule = SigmaRule.query.get(rule_id)
        if rule:
            sigma_rules.append(rule.content)
    
    # Execute the hunt
    results = execute_hunt(hunt_obj.id, sigma_rules, time_range)
    
    flash(f"Executed {len(results)} rules as part of hunt '{hunt_name}'", "success")
    return redirect(url_for('hunt_detail', hunt_id=hunt_obj.id))


@app.errorhandler(500)
def internal_server_error(e):
    return render_template('base.html', error="Internal server error"), 500
