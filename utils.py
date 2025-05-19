import os
import json
import logging
import requests
import tempfile
import subprocess
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timedelta
from fuzzywuzzy import process, fuzz
from models import FieldMapping, SplunkSettings, QueryHistory
from app import db

# Disable insecure HTTPS request warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def convert_sigma_to_spl(sigma_rule, field_mapping=None):
    """
    Convert a Sigma rule to Splunk SPL query using sigmac
    
    Args:
        sigma_rule (str): The Sigma rule content
        field_mapping (dict, optional): Field mapping to use for conversion
        
    Returns:
        tuple: (spl_query, error_message)
    """
    try:
        # Create a temporary file for the Sigma rule
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.yml', delete=False) as temp_sigma:
            temp_sigma.write(sigma_rule)
            temp_sigma_path = temp_sigma.name
        
        # Create a temporary file for field mappings if provided
        temp_config_path = None
        if field_mapping:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.yml', delete=False) as temp_config:
                yaml_content = "fieldmappings:\n"
                for sigma_field, splunk_field in field_mapping.items():
                    yaml_content += f"  {sigma_field}: {splunk_field}\n"
                temp_config.write(yaml_content)
                temp_config_path = temp_config.name
        
        # Build the sigmac command
        command = ["sigmac", "-t", "splunk", temp_sigma_path]
        if temp_config_path:
            command.extend(["-c", temp_config_path])
        
        # Execute sigmac
        result = subprocess.run(command, capture_output=True, text=True)
        
        # Clean up temporary files
        if os.path.exists(temp_sigma_path):
            os.unlink(temp_sigma_path)
        if temp_config_path and os.path.exists(temp_config_path):
            os.unlink(temp_config_path)
        
        if result.returncode != 0:
            return None, f"Sigma conversion error: {result.stderr}"
        
        return result.stdout.strip(), None
    
    except Exception as e:
        logging.error(f"Error converting Sigma rule: {str(e)}")
        return None, f"Error converting Sigma rule: {str(e)}"

def get_time_range_params(time_range):
    """
    Convert time range string to Splunk time parameters
    
    Args:
        time_range (str): Selected time range (All time, Last 1 year, Last 30 days)
        
    Returns:
        tuple: (earliest_time, latest_time) as strings in Splunk format
    """
    now = datetime.utcnow()
    
    if time_range == "All time":
        return "0", "now"
    elif time_range == "Last 1 year":
        earliest = now - timedelta(days=365)
        return earliest.strftime("%Y-%m-%dT%H:%M:%S"), "now"
    elif time_range == "Last 30 days":
        earliest = now - timedelta(days=30)
        return earliest.strftime("%Y-%m-%dT%H:%M:%S"), "now"
    else:
        # Default to last 24 hours
        earliest = now - timedelta(days=1)
        return earliest.strftime("%Y-%m-%dT%H:%M:%S"), "now"

def execute_splunk_query(query, time_range):
    """
    Execute a Splunk query using Splunk's REST API
    
    Args:
        query (str): The SPL query to execute
        time_range (str): Selected time range (All time, Last 1 year, Last 30 days)
        
    Returns:
        tuple: (results, error_message)
    """
    try:
        # Get Splunk connection settings from database
        settings = SplunkSettings.get_settings()
        if not settings:
            return None, "Splunk connection settings not found"
        
        # Get time range parameters
        earliest_time, latest_time = get_time_range_params(time_range)
        
        # Prepare the request
        url = f"https://{settings.host}:{settings.port}/services/search/jobs/export"
        auth = (settings.username, settings.password)
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        data = {
            "search": query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "output_mode": "json"
        }
        
        # Make the request to Splunk
        response = requests.post(
            url, 
            auth=auth, 
            headers=headers, 
            data=data, 
            verify=False  # Skip SSL certificate verification
        )
        
        if response.status_code != 200:
            return None, f"Splunk API error: {response.status_code} - {response.text}"
        
        # Process the response
        results = []
        for line in response.text.strip().split('\n'):
            if line:
                try:
                    results.append(json.loads(line))
                except json.JSONDecodeError:
                    logging.warning(f"Could not parse Splunk result line: {line}")
        
        return results, None
    
    except Exception as e:
        logging.error(f"Error executing Splunk query: {str(e)}")
        return None, f"Error executing Splunk query: {str(e)}"

def test_splunk_connection(host, port, username, password):
    """
    Test the connection to Splunk's REST API
    
    Args:
        host (str): Splunk host
        port (int): Splunk port
        username (str): Splunk username
        password (str): Splunk password
        
    Returns:
        tuple: (success, message)
    """
    try:
        url = f"https://{host}:{port}/services/server/info"
        auth = (username, password)
        headers = {
            "Content-Type": "application/json"
        }
        
        response = requests.get(
            url, 
            auth=auth, 
            headers=headers, 
            verify=False  # Skip SSL certificate verification
        )
        
        if response.status_code == 200:
            return True, "Connection successful"
        else:
            return False, f"Connection failed: {response.status_code} - {response.text}"
            
    except Exception as e:
        logging.error(f"Error testing Splunk connection: {str(e)}")
        return False, f"Error testing Splunk connection: {str(e)}"

def save_query_results(sigma_rule, splunk_query, results, time_range, status="Success", error_message=None):
    """
    Save query results to the database
    
    Args:
        sigma_rule (str): Original Sigma rule
        splunk_query (str): Converted Splunk query
        results (list): Query results
        time_range (str): Time range used for the query
        status (str): Query status (Success, Failed, etc.)
        error_message (str, optional): Error message if query failed
        
    Returns:
        QueryHistory: The saved query history record
    """
    try:
        query_history = QueryHistory(
            sigma_rule=sigma_rule,
            splunk_query=splunk_query,
            results=results,
            time_range=time_range,
            status=status,
            error_message=error_message
        )
        
        db.session.add(query_history)
        db.session.commit()
        
        return query_history
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error saving query results: {str(e)}")
        return None

def suggest_field_mappings(current_mappings, sigma_rule):
    """
    Suggest new field mappings based on fuzzy matching
    
    Args:
        current_mappings (dict): Current field mappings
        sigma_rule (str): Sigma rule content to analyze
        
    Returns:
        dict: Suggested field mappings
    """
    try:
        # Extract potential field names from the Sigma rule
        # This is a simplified approach - actual implementation would need more sophisticated parsing
        sigma_fields = set()
        for line in sigma_rule.split('\n'):
            if ':' in line and not line.strip().startswith('#'):
                # Extract field from lines like "field_name: value" or "field_name>: value"
                parts = line.split(':', 1)
                if len(parts) == 2:
                    field = parts[0].strip().rstrip('>').strip()
                    if '.' in field:  # Likely a field reference
                        sigma_fields.add(field)
        
        # Fields already mapped
        mapped_sigma_fields = set(current_mappings.keys())
        
        # Fields that need mapping suggestions
        unmapped_fields = sigma_fields - mapped_sigma_fields
        
        # Generate suggestions
        suggestions = {}
        for field in unmapped_fields:
            # Check if any existing mappings are similar
            if current_mappings:
                matches = process.extract(
                    field, 
                    current_mappings.keys(), 
                    scorer=fuzz.token_sort_ratio, 
                    limit=3
                )
                
                best_matches = [m for m in matches if m[1] >= 70]  # Only use matches above 70% similarity
                
                if best_matches:
                    # Use the mapping of the most similar field
                    suggested_value = current_mappings[best_matches[0][0]]
                    
                    # If the field has parts (e.g., user.name), try to extract the last part
                    if '.' in field:
                        parts = field.split('.')
                        fallback_suggestion = parts[-1]
                        
                        # If the suggested value doesn't seem relevant, use the last part
                        if fuzz.ratio(suggested_value, fallback_suggestion) < 50:
                            suggested_value = fallback_suggestion
                else:
                    # No good match found, extract the last part of the field name
                    if '.' in field:
                        suggested_value = field.split('.')[-1]
                    else:
                        suggested_value = field
            else:
                # No existing mappings, extract the last part of the field name
                if '.' in field:
                    suggested_value = field.split('.')[-1]
                else:
                    suggested_value = field
            
            suggestions[field] = suggested_value
        
        return suggestions
    
    except Exception as e:
        logging.error(f"Error generating field mapping suggestions: {str(e)}")
        return {}
