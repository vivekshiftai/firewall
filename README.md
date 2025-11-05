# Cross-Firewall Policy Analysis Engine

A production-grade FastAPI application for CROSS-FIREWALL policy analysis and compliance.

## Features

1. **Single Firewall Analysis** - Detect internal inconsistencies within ONE firewall config
2. **Multi-Firewall Comparison** - Compare policies between Fortinet and Zscaler
3. **Policy Standardization** - Identify differences in approach/coverage
4. **Compliance Gap Analysis** - Find policies missing in one firewall vs. the other
5. **Generate Cross-Firewall Reports** - Policy parity matrix and recommendations
6. **Conflict Detection** - Identify contradictory policies between firewalls
7. **Coverage Analysis** - Analyze policy coverage gaps between platforms
8. **Enforcement Comparison** - Compare security capabilities between vendors
9. **Multi-Format Export** - Export reports in JSON, CSV, and PDF formats

## Supported Firewalls

- Fortinet FortiGate (source: JSON config exports)
- Zscaler Cloud Security (source: API JSON responses or config exports)
- Extensible to: Cisco ASA, Palo Alto Networks, pfSense

## Quick Start

### Using Docker (Recommended)

```bash
# Build and run the application
docker-compose up --build

# The API will be available at http://localhost:8000
```

### Using Python

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
uvicorn main:app --reload
```

## API Endpoints

### Core Analysis Endpoints
- `GET /` - Health check
- `POST /api/v1/parse-config` - Parse firewall configuration
- `POST /api/v1/analyze-single` - Analyze single firewall
- `POST /api/v1/compare-firewalls` - Compare two firewalls
- `POST /api/v1/check-compliance` - Check compliance
- `POST /api/v1/generate-report` - Generate report

### Multi-Firewall Analysis Endpoints
- `POST /api/v1/analyze/multi-firewall` - Complete cross-firewall analysis
- `POST /api/v1/compare/policies` - Compare policy sets between vendors
- `GET /api/v1/vendors` - List supported vendors
- `GET /api/v1/vendors/{vendor}/schema` - Get vendor configuration schema
- `POST /api/v1/validate/config/{vendor}` - Validate vendor configuration

### Analysis Results Endpoints
- `GET /api/v1/analysis/{id}` - Get complete analysis report
- `GET /api/v1/analysis/{id}/policy-matches` - Get policy match matrix
- `GET /api/v1/analysis/{id}/coverage` - Get coverage analysis
- `GET /api/v1/analysis/{id}/conflicts` - Get conflict report
- `GET /api/v1/analysis/{id}/enforcement-matrix` - Get enforcement capabilities
- `GET /api/v1/analysis/{id}/export` - Export analysis in various formats
- `POST /api/v1/audit/check-policy` - Check policy compliance

## Architecture

The application follows a modular architecture with the following components:

1. **Models** - Pydantic models for data validation and cross-firewall analysis
2. **Parsers** - Vendor-specific configuration parsers with factory pattern
3. **Analyzers** - Policy analysis and comparison engines
4. **Core Components** - Specialized modules for matching, coverage, conflicts, and reporting
5. **Services** - Orchestration layer for complex operations
6. **API** - FastAPI endpoints organized by functionality
7. **Reports** - Multi-format report generation
8. **Vendors** - Vendor-specific implementations with abstract base classes
9. **Utils** - Utility functions and semantic mapping
10. **Tests** - Comprehensive unit tests

## Core Modules

### Policy Matching
- Cross-firewall policy matching with weighted similarity scoring
- Exact, semantic, and partial match detection
- Confidence scoring based on source, destination, service, and action

### Coverage Analysis
- Bidirectional coverage percentage calculation
- Coverage gap identification with severity classification
- Enforcement capability matrix generation

### Conflict Detection
- Security policy contradiction detection (allow vs deny)
- Enforcement mechanism differences
- Priority conflict identification

### Report Generation
- Executive summary generation
- Multi-format export (JSON, CSV, PDF)
- Standardization recommendations
- Detailed policy mappings

## Testing

Run the test suite:

```bash
python -m tests.test_runner
```

## License

This project is licensed under the MIT License.