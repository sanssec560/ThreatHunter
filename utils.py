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
    Convert a Sigma rule to Splunk SPL query using sigma-cli
    This is the most recent and reliable way to convert Sigma rules
    
    Args:
        sigma_rule (str): The Sigma rule content
        field_mapping (dict, optional): Field mapping to use for conversion
        
    Returns:
        tuple: (spl_query, error_message)
    """
    try:
        import tempfile
        import subprocess
        import os
        import json
        
        # Create a temporary file for the sigma rule
        try:
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.yml', delete=False) as temp_file:
                temp_file.write(sigma_rule)
                temp_path = temp_file.name
            
            # Create a temporary file for field mappings if provided
            mapping_path = None
            if field_mapping:
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as map_file:
                    json.dump({"fieldmappings": field_mapping}, map_file)
                    mapping_path = map_file.name
            
            # Build the sigma command
            command = ["sigma", "convert", "-t", "splunk", "-f", "default", temp_path]
            
            # Add mapping file if provided
            if mapping_path:
                command.extend(["--mapping", mapping_path])
            
            # Execute the command
            result = subprocess.run(command, capture_output=True, text=True)
            
            # Clean up temporary files
            os.unlink(temp_path)
            if mapping_path:
                os.unlink(mapping_path)
            
            if result.returncode != 0:
                return None, f"Sigma conversion error: {result.stderr}"
            
            # Get the output and clean it up
            splunk_query = result.stdout.strip()
            
            # Customize query for specific rule categories if needed
            import yaml
            sigma_yaml = yaml.safe_load(sigma_rule)
            
            # Add special handling for Windows process creation events
            if sigma_yaml and 'logsource' in sigma_yaml:
                logsource = sigma_yaml['logsource']
                if 'category' in logsource and logsource['category'] == 'process_creation' and 'product' in logsource and logsource['product'] == 'windows':
                    # Ensure the query includes the Security log source for Windows
                    if 'source="WinEventLog:Security"' not in splunk_query:
                        splunk_query = splunk_query.replace('index=windows', 'index=* source="WinEventLog:Security"')
                    
                    # Ensure EventCode is specified
                    if 'EventCode=4688' not in splunk_query:
                        if 'AND' in splunk_query:
                            splunk_query = splunk_query.replace('AND', 'AND EventCode=4688 AND', 1)
                        else:
                            splunk_query += ' AND EventCode=4688'
            
            # Handle the contains|all modifiers that might not be properly converted
            if '|contains|all' in sigma_rule:
                # Replace any OR operators between values of the same field with AND operators
                # This is a simplistic approach, for production a more robust parser would be needed
                import re
                fields = re.findall(r'(\w+)\|contains\|all', sigma_rule)
                for field in fields:
                    # Find patterns like (field="*val1*" OR field="*val2*") and convert to AND
                    pattern = re.compile(rf'\(\s*{field}="[^"]*"\s+OR\s+(?:{field}="[^"]*"\s+OR\s+)*{field}="[^"]*"\s*\)')
                    matches = pattern.findall(splunk_query)
                    for match in matches:
                        # Replace OR with AND in this match
                        new_match = match.replace(' OR ', ' AND ')
                        splunk_query = splunk_query.replace(match, new_match)
            
            return splunk_query, None
            
        except yaml.YAMLError as e:
            return None, f"Invalid YAML format: {str(e)}"
            
    except Exception as e:
        logging.error(f"Error converting Sigma rule: {str(e)}")
        return None, f"Error converting Sigma rule: {str(e)}"
    
    finally:
        # Clean up any temporary files if they exist
        if 'temp_path' in locals() and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except:
                pass
                
        if 'mapping_path' in locals() and mapping_path and os.path.exists(mapping_path):
            try:
                os.unlink(mapping_path)
            except:
                pass

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
