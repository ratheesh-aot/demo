"""
BC Building Code Rule Engine - Flask API Service
Handles PDF extraction, rule management, and permit validation using Claude AI
"""

import os
import json
import base64
import logging
from datetime import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
import anthropic
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('rule-engine.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# Configuration
ANTHROPIC_API_KEY = os.getenv('ANTHROPIC_API_KEY', 'your-api-key-here')
RULES_FILE_PATH = os.getenv('RULES_FILE_PATH', '../demo-rules.json')

logger.info(f"Starting BC Building Code Rule Engine API")
logger.info(f"Rules file path: {RULES_FILE_PATH}")
logger.info(f"Anthropic API key configured: {'Yes' if ANTHROPIC_API_KEY != 'your-api-key-here' else 'No'}")

client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)


def extract_text_from_pdf_with_claude(pdf_base64: str, extraction_type: str) -> dict:
    """
    Extract structured data from PDF using Claude's vision capabilities
    
    Args:
        pdf_base64: Base64 encoded PDF content
        extraction_type: 'rules' or 'permit'
    
    Returns:
        Extracted structured data as dict
    """
    logger.info(f"Starting PDF extraction - Type: {extraction_type}")
    logger.debug(f"PDF base64 length: {len(pdf_base64) if pdf_base64 else 0} characters")
    
    if extraction_type == 'rules':
        prompt = """Analyze this BC Building Code document and extract the TOP 3 MOST IMPORTANT building rules only.

For each rule, extract:
- Rule title and description (be concise)
- Building types it applies to
- Conditions when the rule applies
- Requirements that must be met
- Dimensional limits (height, area, etc.)

Return a JSON object with this structure:
{
  "rules": [
    {
      "title": "Rule title",
      "description": "Concise description",
      "category": "dimensional",
      "building_types": ["residential"],
      "conditions": [
        {
          "field": "building.storeys",
          "operator": "eq",
          "value": 1,
          "description": "Building must be single-storey"
        }
      ],
      "requirements": [
        {
          "field": "building.height.value",
          "operator": "lte",
          "value": 4.5,
          "unit": "meters",
          "description": "Maximum building height",
          "error_message": "Height exceeds maximum"
        }
      ],
      "tags": ["residential", "height"]
    }
  ]
}

IMPORTANT: Return ONLY the 3 most important rules. Be concise. Ensure valid JSON."""

    else:  # permit
        prompt = """Analyze this building permit application and extract all relevant information.

Extract:
- Building details (type, storeys, height, floor area)
- Property information
- Construction details
- Any dimensional specifications
- Special features (mezzanines, accessory structures, etc.)

Return a JSON object with this structure:
{
  "permit": {
    "application_id": "extracted or generated ID",
    "building": {
      "use": "residential|commercial|industrial|accessory|mixed",
      "storeys": 1,
      "height": {
        "value": 4.2,
        "unit": "meters"
      },
      "floor_area": {
        "total": 1500,
        "unit": "sqft"
      },
      "occupancy_class": "small|medium|large",
      "has_mezzanine": false,
      "attached": false
    },
    "property": {
      "address": "extracted address",
      "lot_size": "if available"
    },
    "applicant": {
      "name": "extracted name",
      "contact": "extracted contact"
    }
  }
}

Extract all numeric values precisely with their units."""

    try:
        logger.info("Calling Claude API...")
        logger.debug(f"Model: claude-opus-4-6, Max tokens: 8000")
        
        message = client.messages.create(
            model="claude-opus-4-6",
            max_tokens=8000,
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "document",
                            "source": {
                                "type": "base64",
                                "media_type": "application/pdf",
                                "data": pdf_base64
                            }
                        },
                        {
                            "type": "text",
                            "text": prompt
                        }
                    ]
                }
            ]
        )
        
        logger.info("Claude API call successful")
        logger.debug(f"Response usage - Input tokens: {message.usage.input_tokens}, Output tokens: {message.usage.output_tokens}")
        
        # Extract JSON from response
        response_text = message.content[0].text
        logger.debug(f"Claude response length: {len(response_text)} characters")
        logger.debug(f"Claude response preview: {response_text[:200]}...")
        
        # Remove markdown code blocks if present
        if response_text.strip().startswith('```'):
            logger.info("Removing markdown code blocks from response")
            # Find the first { and last }
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
        else:
            # Try to find JSON in the response
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}') + 1
        
        if start_idx != -1 and end_idx > start_idx:
            json_str = response_text[start_idx:end_idx]
            logger.debug(f"Extracted JSON string length: {len(json_str)} characters")
            
            try:
                result = json.loads(json_str)
                logger.info(f"Successfully parsed JSON response")
                return result
            except json.JSONDecodeError as e:
                logger.error(f"JSON parse error: {str(e)}")
                logger.error(f"JSON string around error position: {json_str[max(0, e.pos-100):min(len(json_str), e.pos+100)]}")
                
                # Try to fix common JSON issues
                logger.info("Attempting to fix JSON...")
                # Remove trailing commas before closing braces/brackets
                import re
                json_str_fixed = re.sub(r',(\s*[}\]])', r'\1', json_str)
                
                try:
                    result = json.loads(json_str_fixed)
                    logger.info("Successfully parsed JSON after fixing")
                    return result
                except json.JSONDecodeError as e2:
                    logger.error(f"Still failed after fix: {str(e2)}")
                    raise ValueError(f"Invalid JSON from Claude: {str(e)}")
        else:
            logger.error("No JSON found in Claude response")
            raise ValueError("No JSON found in Claude response")
            
    except Exception as e:
        logger.error(f"Claude API error: {str(e)}", exc_info=True)
        raise Exception(f"Claude API error: {str(e)}")


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    logger.debug("Health check requested")
    return jsonify({
        "status": "healthy",
        "service": "BC Building Code Rule Engine API",
        "timestamp": datetime.utcnow().isoformat()
    })


@app.route('/debug-request', methods=['POST'])
def debug_request():
    """Debug endpoint to see what data is being received"""
    logger.info("=== Debug Request Received ===")
    try:
        data = request.get_json()
        logger.info(f"Full request data: {json.dumps(data, indent=2)}")
        
        return jsonify({
            "success": True,
            "received_data": data,
            "data_keys": list(data.keys()) if data else [],
            "pdf_base64_length": len(data.get('pdf_base64', '')) if data else 0,
            "pdf_base64_preview": data.get('pdf_base64', '')[:500] if data else None
        })
    except Exception as e:
        logger.error(f"Error in debug_request: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/extract-rules', methods=['POST'])
def extract_rules():
    """
    Extract building rules from BC Building Code PDF
    
    Request body:
    {
        "pdf_base64": "base64 encoded PDF content",
        "document_info": {
            "title": "BC Building Code 2024",
            "version": "1.0"
        }
    }
    
    Returns:
    {
        "success": true,
        "rules": [...],
        "extracted_count": 3
    }
    """
    logger.info("=== Extract Rules Request Received ===")
    try:
        data = request.get_json()
        logger.debug(f"Request data keys: {list(data.keys()) if data else 'None'}")
        
        if not data or 'pdf_base64' not in data:
            logger.error("Missing pdf_base64 in request body")
            return jsonify({
                "success": False,
                "error": "Missing pdf_base64 in request body"
            }), 400
        
        pdf_base64 = data['pdf_base64']
        document_info = data.get('document_info', {})
        
        logger.info(f"Document info: {document_info}")
        logger.debug(f"PDF base64 length: {len(pdf_base64)}")
        logger.debug(f"PDF base64 first 200 chars: {pdf_base64[:200]}")
        
        # Check if pdf_base64 is actually a JSON string that needs parsing
        if pdf_base64.strip().startswith('{') or pdf_base64.strip().startswith('"'):
            logger.warning("PDF base64 appears to be JSON string, attempting to parse...")
            try:
                # Try to parse as JSON
                parsed = json.loads(pdf_base64)
                if isinstance(parsed, dict):
                    # It's the file object, extract the url field
                    if 'url' in parsed:
                        url = parsed['url']
                        comma_idx = url.find(',')
                        if comma_idx > -1:
                            pdf_base64 = url[comma_idx + 1:]
                            logger.info(f"Extracted base64 from parsed JSON, new length: {len(pdf_base64)}")
                elif isinstance(parsed, str):
                    # It's a string, might be the url
                    comma_idx = parsed.find(',')
                    if comma_idx > -1:
                        pdf_base64 = parsed[comma_idx + 1:]
                        logger.info(f"Extracted base64 from parsed string, new length: {len(pdf_base64)}")
            except json.JSONDecodeError:
                logger.warning("Failed to parse as JSON, treating as raw base64")
        
        # Validate base64 data
        if len(pdf_base64) < 1000:
            logger.error(f"PDF base64 data too short ({len(pdf_base64)} chars). Likely not actual PDF data.")
            logger.error(f"Received data: {pdf_base64[:500]}")
            return jsonify({
                "success": False,
                "error": f"Invalid PDF data. Received only {len(pdf_base64)} characters. Expected base64 encoded PDF content, but got: {pdf_base64[:200]}"
            }), 400
        
        # Check if it's valid base64
        try:
            import base64
            base64.b64decode(pdf_base64[:100])  # Test decode first 100 chars
            logger.info("Base64 validation passed")
        except Exception as e:
            logger.error(f"Invalid base64 encoding: {str(e)}")
            return jsonify({
                "success": False,
                "error": f"Invalid base64 encoding: {str(e)}"
            }), 400
        
        # Extract rules using Claude
        logger.info("Starting rule extraction with Claude...")
        extracted_data = extract_text_from_pdf_with_claude(pdf_base64, 'rules')
        
        # Enrich rules with metadata
        rules = extracted_data.get('rules', [])
        logger.info(f"Extracted {len(rules)} rules from PDF")
        
        current_date = datetime.utcnow().strftime('%Y-%m-%d')
        
        for idx, rule in enumerate(rules, start=1):
            logger.debug(f"Processing rule {idx}: {rule.get('title', 'Untitled')}")
            
            # Generate rule ID if not present
            if 'rule_id' not in rule:
                rule['rule_id'] = f"RULE-{idx:06d}"
                logger.debug(f"Generated rule_id: {rule['rule_id']}")
            
            # Add default fields
            rule.setdefault('effective_date', current_date)
            rule.setdefault('expiry_date', None)
            rule.setdefault('supersedes', None)
            rule.setdefault('superseded_by', None)
            rule.setdefault('status', 'draft')
            rule.setdefault('severity', 'mandatory')
            rule.setdefault('amendment_history', [])
            rule.setdefault('compliance_examples', [])
            
            # Add source document reference
            rule['source_document'] = {
                "document_id": f"DOC-{datetime.utcnow().strftime('%Y%m%d')}-{idx:03d}",
                "title": document_info.get('title', 'BC Building Code'),
                "version": document_info.get('version', '1.0'),
                "page_reference": str(idx),
                "storage_path": f"/documents/bcbc/{document_info.get('title', 'document').replace(' ', '_')}.pdf"
            }
        
        logger.info(f"Successfully extracted and enriched {len(rules)} rules")
        
        return jsonify({
            "success": True,
            "rules": rules,
            "extracted_count": len(rules),
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in extract_rules: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/get-rules', methods=['GET'])
def get_rules():
    """
    Fetch current rules from demo-rules.json
    
    Returns:
    {
        "success": true,
        "rules": [...],
        "metadata": {...}
    }
    """
    logger.info("=== Get Rules Request Received ===")
    try:
        rules_path = Path(RULES_FILE_PATH)
        logger.debug(f"Rules file path: {rules_path.absolute()}")
        
        if not rules_path.exists():
            logger.error(f"Rules file not found at: {rules_path.absolute()}")
            return jsonify({
                "success": False,
                "error": "Rules file not found"
            }), 404
        
        logger.info(f"Reading rules from: {rules_path.absolute()}")
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules_data = json.load(f)
        
        rules_count = len(rules_data.get('rules', []))
        logger.info(f"Successfully loaded {rules_count} rules")
        logger.debug(f"Metadata: {rules_data.get('metadata', {})}")
        
        return jsonify({
            "success": True,
            "rules": rules_data.get('rules', []),
            "metadata": rules_data.get('metadata', {}),
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in get_rules: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/save-rules', methods=['POST'])
def save_rules():
    """
    Save or update rules in demo-rules.json
    
    Request body:
    {
        "rules": [...],
        "mode": "append|replace",
        "updated_by": "admin_user"
    }
    
    Returns:
    {
        "success": true,
        "message": "Rules saved successfully",
        "total_rules": 5
    }
    """
    logger.info("=== Save Rules Request Received ===")
    try:
        data = request.get_json()
        logger.debug(f"Request data keys: {list(data.keys()) if data else 'None'}")
        
        if not data or 'rules' not in data:
            logger.error("Missing rules in request body")
            return jsonify({
                "success": False,
                "error": "Missing rules in request body"
            }), 400
        
        new_rules = data['rules']
        mode = data.get('mode', 'append')
        updated_by = data.get('updated_by', 'system')
        
        logger.info(f"Save mode: {mode}, Updated by: {updated_by}")
        logger.info(f"Number of rules to save: {len(new_rules)}")
        
        rules_path = Path(RULES_FILE_PATH)
        logger.debug(f"Rules file path: {rules_path.absolute()}")
        
        # Load existing rules
        if rules_path.exists():
            logger.info("Loading existing rules file")
            with open(rules_path, 'r', encoding='utf-8') as f:
                existing_data = json.load(f)
            logger.debug(f"Existing rules count: {len(existing_data.get('rules', []))}")
        else:
            logger.info("Creating new rules file")
            existing_data = {
                "rules": [],
                "metadata": {
                    "schema_version": "1.0.0",
                    "total_rules": 0,
                    "active_rules": 0,
                    "source_documents": []
                }
            }
        
        # Update rules based on mode
        if mode == 'replace':
            logger.info("Replacing all existing rules")
            existing_data['rules'] = new_rules
        else:  # append
            logger.info("Appending/updating rules")
            # Merge rules, avoiding duplicates by rule_id
            existing_rule_ids = {r['rule_id'] for r in existing_data['rules']}
            logger.debug(f"Existing rule IDs: {existing_rule_ids}")
            
            for rule in new_rules:
                rule_id = rule['rule_id']
                if rule_id not in existing_rule_ids:
                    logger.debug(f"Adding new rule: {rule_id}")
                    existing_data['rules'].append(rule)
                else:
                    logger.debug(f"Updating existing rule: {rule_id}")
                    # Update existing rule
                    for idx, existing_rule in enumerate(existing_data['rules']):
                        if existing_rule['rule_id'] == rule_id:
                            existing_data['rules'][idx] = rule
                            break
        
        # Update metadata
        existing_data['metadata']['last_updated'] = datetime.utcnow().isoformat() + 'Z'
        existing_data['metadata']['updated_by'] = updated_by
        existing_data['metadata']['total_rules'] = len(existing_data['rules'])
        existing_data['metadata']['active_rules'] = sum(
            1 for r in existing_data['rules'] if r.get('status') == 'active'
        )
        
        logger.info(f"Updated metadata - Total: {existing_data['metadata']['total_rules']}, Active: {existing_data['metadata']['active_rules']}")
        
        # Collect unique source documents
        source_docs = set()
        for rule in existing_data['rules']:
            if 'source_document' in rule:
                source_docs.add(rule['source_document'].get('document_id', ''))
        existing_data['metadata']['source_documents'] = sorted(list(source_docs))
        logger.debug(f"Source documents: {existing_data['metadata']['source_documents']}")
        
        # Save to file
        logger.info(f"Writing rules to file: {rules_path.absolute()}")
        with open(rules_path, 'w', encoding='utf-8') as f:
            json.dump(existing_data, f, indent=2, ensure_ascii=False)
        
        logger.info("Rules saved successfully")
        
        return jsonify({
            "success": True,
            "message": "Rules saved successfully",
            "total_rules": existing_data['metadata']['total_rules'],
            "active_rules": existing_data['metadata']['active_rules'],
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in save_rules: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/extract-permit', methods=['POST'])
def extract_permit():
    """
    Extract permit data from building permit application PDF
    
    Request body:
    {
        "pdf_base64": "base64 encoded PDF content"
    }
    
    Returns:
    {
        "success": true,
        "permit": {...}
    }
    """
    logger.info("=== Extract Permit Request Received ===")
    try:
        data = request.get_json()
        logger.debug(f"Request data keys: {list(data.keys()) if data else 'None'}")
        
        if not data or 'pdf_base64' not in data:
            logger.error("Missing pdf_base64 in request body")
            return jsonify({
                "success": False,
                "error": "Missing pdf_base64 in request body"
            }), 400
        
        pdf_base64 = data['pdf_base64']
        logger.debug(f"PDF base64 length: {len(pdf_base64)}")
        
        # Extract permit using Claude
        logger.info("Starting permit extraction with Claude...")
        extracted_data = extract_text_from_pdf_with_claude(pdf_base64, 'permit')
        
        permit = extracted_data.get('permit', {})
        logger.info(f"Successfully extracted permit data")
        logger.debug(f"Permit building type: {permit.get('building', {}).get('type', 'Unknown')}")
        
        return jsonify({
            "success": True,
            "permit": permit,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in extract_permit: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@app.route('/validate-permit', methods=['POST'])
def validate_permit():
    """
    Validate permit data against rule engine
    
    Request body:
    {
        "permit": {...},
        "rules": [...] (optional, will fetch from file if not provided)
    }
    
    Returns:
    {
        "success": true,
        "valid": true/false,
        "violations": [...],
        "summary": {...}
    }
    """
    logger.info("=== Validate Permit Request Received ===")
    try:
        data = request.get_json()
        logger.debug(f"Request data keys: {list(data.keys()) if data else 'None'}")
        
        if not data or 'permit' not in data:
            logger.error("Missing permit in request body")
            return jsonify({
                "success": False,
                "error": "Missing permit in request body"
            }), 400
        
        permit = data['permit']
        logger.info(f"Validating permit for building type: {permit.get('building', {}).get('type', 'Unknown')}")
        logger.debug(f"Permit data: {json.dumps(permit, indent=2)}")
        
        # Get rules
        if 'rules' in data:
            logger.info("Using rules from request body")
            rules = data['rules']
        else:
            logger.info("Fetching rules from file")
            # Fetch from file
            rules_path = Path(RULES_FILE_PATH)
            if rules_path.exists():
                with open(rules_path, 'r', encoding='utf-8') as f:
                    rules_data = json.load(f)
                    rules = rules_data.get('rules', [])
                logger.info(f"Loaded {len(rules)} rules from file")
            else:
                logger.warning("Rules file not found, using empty rules list")
                rules = []
        
        # Validate permit against rules
        violations = []
        applicable_rules = []
        
        logger.info(f"Starting validation against {len(rules)} rules")
        
        for rule in rules:
            rule_id = rule.get('rule_id', 'Unknown')
            
            # Skip non-active rules
            if rule.get('status') != 'active':
                logger.debug(f"Skipping non-active rule: {rule_id}")
                continue
            
            logger.debug(f"Checking rule: {rule_id} - {rule.get('title', 'Untitled')}")
            
            # Check if rule applies to this permit
            conditions_met = check_conditions(permit, rule.get('conditions', []))
            
            if not conditions_met:
                logger.debug(f"Rule {rule_id} conditions not met, skipping")
                continue
            
            logger.info(f"Rule {rule_id} applies to this permit")
            applicable_rules.append(rule_id)
            
            # Check requirements
            requirements = rule.get('requirements', [])
            logger.debug(f"Checking {len(requirements)} requirements for rule {rule_id}")
            
            for req_idx, requirement in enumerate(requirements, 1):
                requirement_met = check_requirement(permit, requirement)
                
                if not requirement_met:
                    violation = {
                        "rule_id": rule_id,
                        "rule_title": rule.get('title', ''),
                        "code_reference": rule.get('code_reference', ''),
                        "severity": rule.get('severity', 'mandatory'),
                        "field": requirement['field'],
                        "requirement": requirement.get('description', ''),
                        "error_message": requirement.get('error_message', 'Requirement not met'),
                        "remediation": rule.get('remediation_guidance', '')
                    }
                    violations.append(violation)
                    logger.warning(f"Violation found - Rule: {rule_id}, Field: {requirement['field']}, Error: {violation['error_message']}")
                else:
                    logger.debug(f"Requirement {req_idx} met for rule {rule_id}")
        
        is_valid = len(violations) == 0
        
        logger.info(f"Validation complete - Valid: {is_valid}, Violations: {len(violations)}, Applicable rules: {len(applicable_rules)}")
        
        summary = {
            "total_rules_checked": len(applicable_rules),
            "applicable_rules": applicable_rules,
            "violation_count": len(violations),
            "mandatory_violations": sum(1 for v in violations if v['severity'] == 'mandatory'),
            "advisory_violations": sum(1 for v in violations if v['severity'] == 'advisory')
        }
        
        logger.debug(f"Summary: {summary}")
        
        return jsonify({
            "success": True,
            "valid": is_valid,
            "violations": violations,
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat()
        })
        
    except Exception as e:
        logger.error(f"Error in validate_permit: {str(e)}", exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


def get_nested_value(data: dict, field_path: str):
    """Get value from nested dict using dot notation (e.g., 'building.height.value')"""
    keys = field_path.split('.')
    value = data
    
    logger.debug(f"Getting nested value for path: {field_path}")
    
    for key in keys:
        if isinstance(value, dict) and key in value:
            value = value[key]
        else:
            logger.debug(f"Key '{key}' not found in path '{field_path}'")
            return None
    
    logger.debug(f"Found value: {value} for path: {field_path}")
    return value


def check_conditions(permit: dict, conditions: list) -> bool:
    """Check if all conditions are met (AND logic)"""
    logger.debug(f"Checking {len(conditions)} conditions")
    
    for idx, condition in enumerate(conditions, 1):
        field = condition['field']
        operator = condition['operator']
        expected_value = condition['value']
        
        actual_value = get_nested_value(permit, field)
        
        logger.debug(f"Condition {idx}: {field} {operator} {expected_value}, Actual: {actual_value}")
        
        if actual_value is None:
            logger.debug(f"Condition {idx} failed: field not found")
            return False
        
        if not evaluate_condition(actual_value, operator, expected_value):
            logger.debug(f"Condition {idx} failed: evaluation returned False")
            return False
        
        logger.debug(f"Condition {idx} passed")
    
    logger.debug("All conditions met")
    return True


def check_requirement(permit: dict, requirement: dict) -> bool:
    """Check if a requirement is met"""
    field = requirement['field']
    operator = requirement['operator']
    expected_value = requirement['value']
    
    actual_value = get_nested_value(permit, field)
    
    logger.debug(f"Checking requirement: {field} {operator} {expected_value}, Actual: {actual_value}")
    
    if actual_value is None:
        logger.debug("Requirement failed: field not found")
        return False
    
    result = evaluate_condition(actual_value, operator, expected_value)
    logger.debug(f"Requirement result: {result}")
    return result


def evaluate_condition(actual, operator: str, expected) -> bool:
    """Evaluate a condition based on operator"""
    logger.debug(f"Evaluating: {actual} {operator} {expected}")
    
    try:
        if operator == 'eq':
            result = actual == expected
        elif operator == 'ne':
            result = actual != expected
        elif operator == 'gt':
            result = float(actual) > float(expected)
        elif operator == 'gte':
            result = float(actual) >= float(expected)
        elif operator == 'lt':
            result = float(actual) < float(expected)
        elif operator == 'lte':
            result = float(actual) <= float(expected)
        elif operator == 'in':
            result = actual in expected
        elif operator == 'not_in':
            result = actual not in expected
        elif operator == 'contains':
            result = expected in actual
        elif operator == 'exists':
            result = actual is not None
        else:
            logger.warning(f"Unknown operator: {operator}")
            result = False
        
        logger.debug(f"Evaluation result: {result}")
        return result
        
    except (ValueError, TypeError) as e:
        logger.error(f"Error evaluating condition: {str(e)}")
        return False


if __name__ == '__main__':
    port = int(os.getenv('FLASK_PORT', 5005))
    logger.info(f"=" * 60)
    logger.info(f"Starting Flask application on port {port}")
    logger.info(f"=" * 60)
    app.run(host='0.0.0.0', port=port, debug=True)
