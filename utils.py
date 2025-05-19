import os
import json
import logging
import requests
import tempfile
import subprocess
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime, timedelta
from fuzzywuzzy import process, fuzz
from models import FieldMapping, SplunkSettings, QueryHistory, Hunt, SigmaRule
from app import db

# Disable insecure HTTPS request warnings
try:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except:
    pass

def convert_sigma_to_spl(sigma_rule, field_mapping=None):
    """
    Convert a Sigma rule to Splunk SPL query
    
    Args:
        sigma_rule (str): The Sigma rule content
        field_mapping (dict, optional): Field mapping to use for conversion
        
    Returns:
        tuple: (spl_query, error_message)
    """
    try:
        import yaml
        import re
        import json
        import tempfile
        import subprocess
        import os
        
        # Create a temporary file for the sigma rule
        temp_path = None
        try:
            # First try using sigma-cli
            with tempfile.NamedTemporaryFile(mode='w+', suffix='.yml', delete=False) as temp_file:
                temp_file.write(sigma_rule)
                temp_path = temp_file.name
            
            # Run sigma convert command
            command = ["sigma", "convert", "-t", "splunk", temp_path]
            result = subprocess.run(command, capture_output=True, text=True)
            
            # Clean up temp file
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
                temp_path = None
            
            if result.returncode == 0:
                splunk_query = result.stdout.strip()
            else:
                # If sigma-cli fails, fall back to our custom implementation
                return custom_sigma_to_spl(sigma_rule, field_mapping)
        
            # Parse the sigma rule for post-processing
            sigma_yaml = yaml.safe_load(sigma_rule)
            
            # Post-process the query for specific rule types
            if sigma_yaml and 'logsource' in sigma_yaml:
                logsource = sigma_yaml['logsource']
                
                # Process Windows process creation events
                if ('category' in logsource and logsource['category'] == 'process_creation' and
                    'product' in logsource and logsource['product'] == 'windows'):
                    
                    # Add Security log source
                    if 'source="WinEventLog:Security"' not in splunk_query:
                        splunk_query = splunk_query.replace('index=windows', 'index=* source="WinEventLog:Security"')
                    
                    # Add EventCode
                    if 'EventCode=4688' not in splunk_query:
                        splunk_query = add_event_code_to_query(splunk_query, "4688")
            
            # Apply field mappings if provided
            if field_mapping:
                for sigma_field, splunk_field in field_mapping.items():
                    # Replace the field names in the query
                    splunk_query = re.sub(rf'\b{re.escape(sigma_field)}\b(?==)', splunk_field, splunk_query)
            
            # Handle the contains|all modifiers specially
            if '|contains|all' in sigma_rule:
                # Find fields with contains|all modifier
                field_matches = re.findall(r'(\w+)\|contains\|all', sigma_rule)
                for field in field_matches:
                    # Find patterns like (field="*val1*" OR field="*val2*") and convert to AND
                    pattern = re.compile(rf'\(\s*({field})="[^"]*"\s+OR\s+(?:\1="[^"]*"\s+OR\s+)*\1="[^"]*"\s*\)')
                    matches = pattern.findall(splunk_query)
                    if matches:
                        for match in matches:
                            # Get the full pattern match
                            pattern = re.compile(rf'\(\s*{re.escape(match)}="[^"]*"\s+OR\s+(?:{re.escape(match)}="[^"]*"\s+OR\s+)*{re.escape(match)}="[^"]*"\s*\)')
                            full_matches = pattern.findall(splunk_query)
                            for full_match in full_matches:
                                new_match = full_match.replace(' OR ', ' AND ')
                                splunk_query = splunk_query.replace(full_match, new_match)
            
            return splunk_query, None
        
        except yaml.YAMLError as e:
            return None, f"Invalid YAML format: {str(e)}"
        
    except Exception as e:
        logging.error(f"Error converting Sigma rule: {str(e)}")
        return None, f"Error converting Sigma rule: {str(e)}"
    
    finally:
        # Clean up any temporary files if they exist
        if temp_path and os.path.exists(temp_path):
            try:
                os.unlink(temp_path)
            except:
                pass

def add_event_code_to_query(query, event_code):
    """Add EventCode to a Splunk query if it doesn't exist"""
    if 'AND' in query:
        parts = query.split('AND', 1)
        return f"{parts[0]}AND EventCode={event_code} AND{parts[1]}"
    else:
        return f"{query} AND EventCode={event_code}"

def custom_sigma_to_spl(sigma_rule, field_mapping=None):
    """
    Custom implementation of Sigma to SPL conversion
    Used as a fallback when sigma-cli is not available or fails
    """
    try:
        import yaml
        import re
        
        # Parse the sigma rule
        try:
            sigma_yaml = yaml.safe_load(sigma_rule)
        except yaml.YAMLError as e:
            return None, f"Invalid YAML format: {str(e)}"
        
        if not sigma_yaml:
            return None, "Empty or invalid Sigma rule"
        
        # Field mapping for common Windows event fields
        windows_field_mapping = {
            'Image': 'NewProcessName',
            'ParentImage': 'ParentProcessName',
            'CommandLine': 'CommandLine',
            'User': 'User',
            'IntegrityLevel': 'IntegrityLevel'
        }
        
        # Combine with user-provided field mapping
        combined_mapping = windows_field_mapping.copy()
        if field_mapping:
            combined_mapping.update(field_mapping)
            
        # Extract detection section
        detection = sigma_yaml.get('detection', {})
        if not detection:
            return None, "No detection section found in Sigma rule"
        
        # Process field modifiers
        def process_field_with_modifiers(field, mapped_field):
            # Handle common Sigma field modifiers
            if '|contains|all' in field:
                base_field = field.split('|')[0]
                if combined_mapping and base_field in combined_mapping:
                    mapped_base = combined_mapping[base_field]
                else:
                    mapped_base = base_field
                return mapped_base, "contains_all"
            elif '|contains' in field:
                base_field = field.split('|')[0]
                if combined_mapping and base_field in combined_mapping:
                    mapped_base = combined_mapping[base_field]
                else:
                    mapped_base = base_field
                return mapped_base, "contains"
            elif '|startswith' in field:
                base_field = field.split('|')[0]
                if combined_mapping and base_field in combined_mapping:
                    mapped_base = combined_mapping[base_field]
                else:
                    mapped_base = base_field
                return mapped_base, "startswith"
            elif '|endswith' in field:
                base_field = field.split('|')[0]
                if combined_mapping and base_field in combined_mapping:
                    mapped_base = combined_mapping[base_field]
                else:
                    mapped_base = base_field
                return mapped_base, "endswith"
            else:
                # Check if base field needs mapping
                if combined_mapping and field in combined_mapping:
                    mapped_field = combined_mapping[field]
                return mapped_field, "equals"
        
        # Helper function to create a Splunk search term
        def create_search_term(field, value, modifier):
            if modifier == "contains_all":
                # Special case for contains_all
                return None
            elif modifier == "contains":
                return f'{field}="*{value}*"'
            elif modifier == "startswith":
                return f'{field}="{value}*"'
            elif modifier == "endswith":
                return f'{field}="*{value}"'
            else:  # equals
                return f'{field}="{value}"'
        
        # Process selection blocks
        selections = {}
        for key, value in detection.items():
            if key == 'condition':
                continue
            
            # Standard field-value pairs dictionary
            if isinstance(value, dict):
                query_parts = []
                for field, field_value in value.items():
                    # Map field name
                    mapped_field, modifier = process_field_with_modifiers(field, field)
                    
                    # Handle different value types and modifiers
                    if modifier == "contains_all" and isinstance(field_value, list):
                        # For "contains|all" modifier, generate AND conditions
                        values_parts = []
                        for v in field_value:
                            values_parts.append(f'{mapped_field}="*{v}*"')
                        if len(values_parts) > 1:
                            value_str = "(" + " AND ".join(values_parts) + ")"
                        else:
                            value_str = values_parts[0]
                        query_parts.append(value_str)
                    elif isinstance(field_value, list):
                        values_parts = []
                        for v in field_value:
                            term = create_search_term(mapped_field, v, modifier)
                            if term:  # Skip None values
                                values_parts.append(term)
                        if len(values_parts) > 1:
                            value_str = "(" + " OR ".join(values_parts) + ")"
                        elif len(values_parts) == 1:
                            value_str = values_parts[0]
                        else:
                            continue  # Skip empty lists
                        query_parts.append(value_str)
                    else:
                        term = create_search_term(mapped_field, field_value, modifier)
                        if term:  # Skip None values
                            query_parts.append(term)
                
                selections[key] = " AND ".join(query_parts)
            
            # Handle list of dictionaries (selection_special type entries)
            elif isinstance(value, list):
                all_condition_parts = []
                
                for item in value:
                    if isinstance(item, dict):
                        field_conditions = []
                        for field, field_value in item.items():
                            # Map the field
                            mapped_field, modifier = process_field_with_modifiers(field, field)
                            
                            # Process values
                            if isinstance(field_value, list):
                                value_parts = []
                                for v in field_value:
                                    term = create_search_term(mapped_field, v, modifier)
                                    if term:
                                        value_parts.append(term)
                                if value_parts:
                                    if len(value_parts) > 1:
                                        field_conditions.append("(" + " OR ".join(value_parts) + ")")
                                    else:
                                        field_conditions.append(value_parts[0])
                            else:
                                term = create_search_term(mapped_field, field_value, modifier)
                                if term:
                                    field_conditions.append(term)
                        
                        if field_conditions:
                            # Join multiple field conditions within one dict as OR
                            all_condition_parts.append("(" + " OR ".join(field_conditions) + ")")
                
                if all_condition_parts:
                    # Join different dicts as OR per the Sigma spec
                    selections[key] = "(" + " OR ".join(all_condition_parts) + ")"
        
        # Process the condition
        condition = detection.get('condition', '')
        if not condition:
            return None, "No condition found in detection section"
        
        # Replace condition syntax
        splunk_condition = condition.lower()
        
        # Handle the "all of X*" syntax
        if "all of" in splunk_condition and "*" in splunk_condition:
            for prefix in [key.split('_')[0] for key in selections.keys() if '_' in key]:
                pattern = f"all of {prefix}*"
                if pattern in splunk_condition:
                    # Find all keys that match the prefix
                    matching_keys = [k for k in selections.keys() if k.startswith(prefix)]
                    if matching_keys:
                        combined = "(" + " AND ".join([f"({selections[k]})" for k in matching_keys]) + ")"
                        splunk_condition = splunk_condition.replace(pattern, combined)
        
        # Replace selection references with their actual queries
        for key, query in selections.items():
            if key in splunk_condition:
                # Wrap complex queries in parentheses
                if ' AND ' in query or ' OR ' in query:
                    splunk_condition = re.sub(r'\b' + re.escape(key) + r'\b', f"({query})", splunk_condition)
                else:
                    splunk_condition = re.sub(r'\b' + re.escape(key) + r'\b', query, splunk_condition)
        
        # Standard condition replacements
        splunk_condition = splunk_condition.replace(" and ", " AND ")
        splunk_condition = splunk_condition.replace(" or ", " OR ")
        splunk_condition = splunk_condition.replace(" not ", " NOT ")
        
        # Build the complete query
        if 'logsource' in sigma_yaml:
            logsource = sigma_yaml['logsource']
            if 'category' in logsource and logsource['category'] == 'process_creation':
                # Standard process creation format
                if 'product' in logsource and logsource['product'] == 'windows':
                    # Specific format for Windows process creation
                    base_query = 'index=* source="WinEventLog:Security" AND EventCode=4688 AND '
                else:
                    base_query = 'index=* EventCode=4688 AND '
            else:
                # Default format
                if 'product' in logsource:
                    base_query = f'index={logsource["product"]} AND '
                else:
                    base_query = 'index=* AND '
        else:
            base_query = 'index=* AND '
        
        # Combine everything
        final_query = base_query + splunk_condition
        
        return final_query, None
    
    except Exception as e:
        logging.error(f"Error in custom Sigma conversion: {str(e)}")
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

def save_query_results(sigma_rule, splunk_query, results, time_range, status="Success", error_message=None, hunt_id=None):
    """
    Save query results to the database
    
    Args:
        sigma_rule (str): Original Sigma rule
        splunk_query (str): Converted Splunk query
        results (list): Query results
        time_range (str): Time range used for the query
        status (str): Query status (Success, Failed, etc.)
        error_message (str, optional): Error message if query failed
        hunt_id (int, optional): ID of the hunt this query belongs to
        
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
            error_message=error_message,
            hunt_id=hunt_id
        )
        
        db.session.add(query_history)
        db.session.commit()
        
        return query_history
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error saving query results: {str(e)}")
        return None


def create_hunt(name, description=""):
    """
    Create a new hunt
    
    Args:
        name (str): Name of the hunt
        description (str, optional): Description of the hunt
        
    Returns:
        Hunt: The created hunt
    """
    try:
        hunt = Hunt(
            name=name,
            description=description
        )
        
        db.session.add(hunt)
        db.session.commit()
        
        return hunt
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error creating hunt: {str(e)}")
        return None


def execute_hunt(hunt_id, sigma_rules, time_range):
    """
    Execute a hunt with multiple Sigma rules
    
    Args:
        hunt_id (int): ID of the hunt
        sigma_rules (list): List of Sigma rules to execute
        time_range (str): Time range for the queries
        
    Returns:
        list: Results for each query
    """
    results = []
    
    # Get the field mapping
    field_mapping = FieldMapping.get_latest_mapping()
    mapping_data = field_mapping.mapping_data if field_mapping else None
    
    # Process each rule
    for sigma_rule in sigma_rules:
        # Convert Sigma to SPL
        splunk_query, error = convert_sigma_to_spl(sigma_rule, mapping_data)
        
        if error:
            # Save failed conversion
            query_record = save_query_results(
                sigma_rule=sigma_rule,
                splunk_query="",
                results=None,
                time_range=time_range,
                status="Failed",
                error_message=error,
                hunt_id=hunt_id
            )
            results.append({
                'query_id': query_record.id if query_record else None,
                'status': "Failed",
                'error': error
            })
            continue
        
        # Execute the query
        query_results, error = execute_splunk_query(splunk_query, time_range)
        
        if error:
            # Save failed execution
            query_record = save_query_results(
                sigma_rule=sigma_rule,
                splunk_query=splunk_query,
                results=None,
                time_range=time_range,
                status="Failed",
                error_message=error,
                hunt_id=hunt_id
            )
            results.append({
                'query_id': query_record.id if query_record else None,
                'status': "Failed",
                'error': error
            })
        else:
            # Save successful execution
            query_record = save_query_results(
                sigma_rule=sigma_rule,
                splunk_query=splunk_query,
                results=query_results,
                time_range=time_range,
                status="Success",
                hunt_id=hunt_id
            )
            results.append({
                'query_id': query_record.id if query_record else None,
                'status': "Success",
                'results_count': len(query_results) if query_results else 0
            })
    
    return results


def save_sigma_rule(title, content, rule_id=None, category=None, product=None):
    """
    Save a Sigma rule to the database
    
    Args:
        title (str): Title of the rule
        content (str): YAML content of the rule
        rule_id (str, optional): ID of the rule
        category (str, optional): Category of the rule
        product (str, optional): Product the rule is for
        
    Returns:
        SigmaRule: The saved rule
    """
    try:
        # Extract rule_id, category, and product from the rule if not provided
        if not rule_id or not category or not product:
            import yaml
            try:
                rule_data = yaml.safe_load(content)
                if rule_data:
                    # Extract rule_id if not provided
                    if not rule_id and 'id' in rule_data:
                        rule_id = rule_data['id']
                    
                    # Extract category and product from logsource if not provided
                    if 'logsource' in rule_data:
                        logsource = rule_data['logsource']
                        if not category and 'category' in logsource:
                            category = logsource['category']
                        if not product and 'product' in logsource:
                            product = logsource['product']
            except Exception as e:
                logging.warning(f"Error parsing rule content: {str(e)}")
        
        # Create and save the rule
        rule = SigmaRule(
            title=title,
            rule_id=rule_id,
            content=content,
            category=category,
            product=product
        )
        
        db.session.add(rule)
        db.session.commit()
        
        return rule
    except Exception as e:
        db.session.rollback()
        logging.error(f"Error saving Sigma rule: {str(e)}")
        return None


def download_sigma_rules(source="sigmahq"):
    """
    Download Sigma rules from the specified source
    
    Args:
        source (str): Source repository ("sigmahq" for official Sigma repository)
        
    Returns:
        tuple: (success, message, count of downloaded rules)
    """
    try:
        import tempfile
        import os
        import requests
        import zipfile
        import yaml
        
        # Default to the SigmaHQ repository
        if source == "sigmahq":
            repo_url = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"
            
            # Create a temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Download the zip file
                response = requests.get(repo_url)
                if response.status_code != 200:
                    return False, f"Failed to download repository: {response.status_code}", 0
                
                # Save the zip file
                zip_path = os.path.join(temp_dir, "sigma.zip")
                with open(zip_path, "wb") as f:
                    f.write(response.content)
                
                # Extract the zip file
                with zipfile.ZipFile(zip_path, "r") as zip_ref:
                    zip_ref.extractall(temp_dir)
                
                # Find the rules directory
                rules_dir = os.path.join(temp_dir, "sigma-master", "rules")
                
                # Process rules
                rule_count = 0
                for root, _, files in os.walk(rules_dir):
                    for file in files:
                        if file.endswith(".yml") or file.endswith(".yaml"):
                            file_path = os.path.join(root, file)
                            
                            # Load the rule
                            with open(file_path, "r", encoding="utf-8") as f:
                                try:
                                    content = f.read()
                                    rule_data = yaml.safe_load(content)
                                    
                                    # Check if it's a valid rule
                                    if isinstance(rule_data, dict) and 'title' in rule_data:
                                        title = rule_data.get('title', 'Untitled Rule')
                                        rule_id = rule_data.get('id', None)
                                        
                                        # Get category and product from logsource
                                        category = None
                                        product = None
                                        if 'logsource' in rule_data:
                                            logsource = rule_data['logsource']
                                            category = logsource.get('category', None)
                                            product = logsource.get('product', None)
                                        
                                        # Save the rule
                                        save_sigma_rule(
                                            title=title,
                                            content=content,
                                            rule_id=rule_id,
                                            category=category,
                                            product=product
                                        )
                                        rule_count += 1
                                except Exception as e:
                                    logging.warning(f"Error processing rule {file_path}: {str(e)}")
                
                return True, f"Successfully downloaded {rule_count} rules", rule_count
        else:
            return False, "Unsupported source", 0
            
    except Exception as e:
        logging.error(f"Error downloading Sigma rules: {str(e)}")
        return False, f"Error downloading Sigma rules: {str(e)}", 0

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
