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
    Convert a Sigma rule to Splunk SPL query
    This implementation handles complex Sigma rules with nested conditions
    
    Args:
        sigma_rule (str): The Sigma rule content
        field_mapping (dict, optional): Field mapping to use for conversion
        
    Returns:
        tuple: (spl_query, error_message)
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
        
        # Extract fields from the detection section
        detection = sigma_yaml.get('detection', {})
        if not detection:
            return None, "No detection section found in Sigma rule"
        
        # Process field modifiers
        def process_field_with_modifiers(field, mapped_field):
            # Handle common Sigma field modifiers
            if '|contains' in field:
                base_field = field.split('|')[0]
                if field_mapping and base_field in field_mapping:
                    mapped_base = field_mapping[base_field]
                else:
                    mapped_base = base_field
                return mapped_base, "contains"
            elif '|startswith' in field:
                base_field = field.split('|')[0]
                if field_mapping and base_field in field_mapping:
                    mapped_base = field_mapping[base_field]
                else:
                    mapped_base = base_field
                return mapped_base, "startswith"
            elif '|endswith' in field:
                base_field = field.split('|')[0]
                if field_mapping and base_field in field_mapping:
                    mapped_base = field_mapping[base_field]
                else:
                    mapped_base = base_field
                return mapped_base, "endswith"
            else:
                return mapped_field, "equals"
        
        # Helper function to create a Splunk search term based on field and value
        def create_search_term(field, value, modifier):
            if modifier == "contains":
                if isinstance(value, str) and '*' in value:
                    # Handle wildcards
                    return f'{field}=*{value}*'
                else:
                    return f'{field}="*{value}*"'
            elif modifier == "startswith":
                return f'{field}="{value}*"'
            elif modifier == "endswith":
                return f'{field}="*{value}"'
            else:  # equals
                if isinstance(value, str) and ' ' in value:
                    return f'{field}="{value}"'
                else:
                    return f'{field}={value}'
        
        # Process each search pattern to handle nested structures
        searches = {}
        for key, value in detection.items():
            if key == 'condition':
                continue
            
            # Handle different types of detection items
            if isinstance(value, dict):
                # Standard field-value pairs
                query_parts = []
                for field, field_value in value.items():
                    # Apply field mapping if available
                    if field_mapping and field.split('|')[0] in field_mapping:
                        mapped_field = field_mapping[field.split('|')[0]]
                    else:
                        mapped_field = field.split('|')[0]
                    
                    # Process field modifiers (contains, startswith, etc.)
                    mapped_field, modifier = process_field_with_modifiers(field, mapped_field)
                    
                    # Handle different value types
                    if isinstance(field_value, list):
                        values_parts = []
                        for v in field_value:
                            values_parts.append(create_search_term(mapped_field, v, modifier))
                        if len(values_parts) > 1:
                            value_str = "(" + " OR ".join(values_parts) + ")"
                        else:
                            value_str = values_parts[0]
                        query_parts.append(value_str)
                    else:
                        query_parts.append(create_search_term(mapped_field, field_value, modifier))
                
                searches[key] = " AND ".join(query_parts)
            
            elif isinstance(value, list):
                # For lists of dicts, handle each entry as a separate condition group
                list_parts = []
                
                for item in value:
                    if isinstance(item, dict):
                        item_parts = []
                        for sub_field, sub_value in item.items():
                            # Apply field mapping
                            if field_mapping and sub_field.split('|')[0] in field_mapping:
                                mapped_sub_field = field_mapping[sub_field.split('|')[0]]
                            else:
                                mapped_sub_field = sub_field.split('|')[0]
                            
                            # Process field modifiers
                            mapped_sub_field, sub_modifier = process_field_with_modifiers(sub_field, mapped_sub_field)
                            
                            # Handle different value types
                            if isinstance(sub_value, list):
                                sub_values_parts = []
                                for v in sub_value:
                                    sub_values_parts.append(create_search_term(mapped_sub_field, v, sub_modifier))
                                if len(sub_values_parts) > 1:
                                    sub_value_str = "(" + " OR ".join(sub_values_parts) + ")"
                                else:
                                    sub_value_str = sub_values_parts[0]
                                item_parts.append(sub_value_str)
                            else:
                                item_parts.append(create_search_term(mapped_sub_field, sub_value, sub_modifier))
                        
                        if item_parts:
                            list_parts.append("(" + " AND ".join(item_parts) + ")")
                
                if list_parts:
                    searches[key] = " OR ".join(list_parts)
        
        # Helper function to convert condition to SPL with support for complex conditions
        def parse_condition(condition, searches):
            # Preprocess the condition - standardize syntax
            condition = re.sub(r'\s+and\s+', ' AND ', condition, flags=re.IGNORECASE)
            condition = re.sub(r'\s+or\s+', ' OR ', condition, flags=re.IGNORECASE)
            condition = re.sub(r'\s+not\s+', ' NOT ', condition, flags=re.IGNORECASE)
            condition = re.sub(r'all\s+of\s+([a-zA-Z0-9_*]+)', r'\1', condition, flags=re.IGNORECASE)
            condition = re.sub(r'1\s+of\s+([a-zA-Z0-9_*]+)', r'\1', condition, flags=re.IGNORECASE)
            
            # Handle special syntax like "all of selection*"
            if "all of" in condition.lower() and "*" in condition:
                pattern = re.compile(r'all\s+of\s+([a-zA-Z0-9_]+)\*', re.IGNORECASE)
                match = pattern.search(condition)
                if match:
                    prefix = match.group(1)
                    wildcard_keys = [k for k in searches.keys() if k.startswith(prefix)]
                    if wildcard_keys:
                        replacement = "(" + " AND ".join([f"({searches[k]})" for k in wildcard_keys]) + ")"
                        condition = pattern.sub(replacement, condition)
            
            # Handle "1 of them" condition
            if "1 of them" in condition.lower():
                # Replace with OR of all search terms
                search_terms = []
                for search_id, search_query in searches.items():
                    search_terms.append(f"({search_query})")
                if search_terms:
                    condition = "(" + " OR ".join(search_terms) + ")"
            
            # Process remaining references to search terms
            for search_id, search_query in searches.items():
                if search_id in condition:
                    # Use word boundary to prevent partial matches
                    pattern = r'\b' + re.escape(search_id) + r'\b'
                    # Wrap in parentheses if it's a complex query
                    if ' AND ' in search_query or ' OR ' in search_query:
                        replacement = f"({search_query})"
                    else:
                        replacement = search_query
                    condition = re.sub(pattern, replacement, condition)
            
            return condition
        
        # Get and process the condition
        condition = detection.get('condition', '')
        if not condition:
            return None, "No condition found in detection section"
        
        # Convert the condition to SPL
        spl_query = parse_condition(condition, searches)
        
        # Build the final SPL query
        query_parts = []
        
        # Add source information from logsource
        if 'logsource' in sigma_yaml:
            logsource = sigma_yaml['logsource']
            index_added = False
            
            # Process logosurce information
            if 'product' in logsource:
                query_parts.append(f"index={logsource['product']}")
                index_added = True
            
            if 'service' in logsource:
                query_parts.append(f"sourcetype={logsource['service']}")
            
            if 'category' in logsource and logsource['category'] == 'process_creation':
                if not index_added:
                    query_parts.append("index=windows")
                query_parts.append("EventCode=4688")
            
        # Add the main search condition
        query_parts.append(spl_query)
        
        # Combine all parts into the final query
        final_query = "search " + " ".join(query_parts)
        
        return final_query, None
    
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
