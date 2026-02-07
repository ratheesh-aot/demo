# BC Building Code Rule Engine - Python API Service

Flask-based REST API for extracting building rules from PDFs, managing rule engine, and validating building permits using Claude AI.

## Features

- Extract building rules from BC Building Code PDFs using Claude AI
- Manage rule engine (fetch, save, update rules)
- Extract permit data from building permit application PDFs
- Validate permits against rule engine with detailed violation reports

## Prerequisites

- Python 3.9+
- Anthropic API key

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Configure environment variables:
```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

3. Run the service:
```bash
python app.py
```

The API will be available at `http://host.docker.internal:5005` (for Docker) or `http://localhost:5000` (for local development)

## API Endpoints

### Health Check
```
GET /health
```

### Extract Rules from PDF
```
POST /extract-rules
Content-Type: application/json

{
  "pdf_base64": "base64_encoded_pdf_content",
  "document_info": {
    "title": "BC Building Code 2024",
    "version": "1.0"
  }
}
```

### Get Current Rules
```
GET /get-rules
```

### Save/Update Rules
```
POST /save-rules
Content-Type: application/json

{
  "rules": [...],
  "mode": "append|replace",
  "updated_by": "admin_user"
}
```

### Extract Permit from PDF
```
POST /extract-permit
Content-Type: application/json

{
  "pdf_base64": "base64_encoded_pdf_content"
}
```

### Validate Permit
```
POST /validate-permit
Content-Type: application/json

{
  "permit": {...},
  "rules": [...] // optional, will fetch from file if not provided
}
```

## Integration with Camunda

This service is designed to be called from Camunda workflows using HTTP connectors:

### Example: Extract Rules Service Task
```xml
<serviceTask id="extractRules" name="Extract Rules from PDF">
  <extensionElements>
    <camunda:connector>
      <camunda:inputOutput>
        <camunda:inputParameter name="url">http://host.docker.internal:5005/extract-rules</camunda:inputParameter>
        <camunda:inputParameter name="method">POST</camunda:inputParameter>
        <camunda:inputParameter name="headers">
          <camunda:map>
            <camunda:entry key="Content-Type">application/json</camunda:entry>
          </camunda:map>
        </camunda:inputParameter>
        <camunda:inputParameter name="payload">
          {
            "pdf_base64": "${pdfBase64}",
            "document_info": {
              "title": "${documentTitle}",
              "version": "${documentVersion}"
            }
          }
        </camunda:inputParameter>
        <camunda:outputParameter name="extractedRules">${response}</camunda:outputParameter>
      </camunda:inputOutput>
      <camunda:connectorId>http-connector</camunda:connectorId>
    </camunda:connector>
  </extensionElements>
</serviceTask>
```

## Error Handling

All endpoints return JSON responses with the following structure:

Success:
```json
{
  "success": true,
  "data": {...},
  "timestamp": "2026-02-05T12:00:00.000000"
}
```

Error:
```json
{
  "success": false,
  "error": "Error message",
  "timestamp": "2026-02-05T12:00:00.000000"
}
```

## Development

Run in debug mode:
```bash
FLASK_DEBUG=True python app.py
```

## License

MIT
