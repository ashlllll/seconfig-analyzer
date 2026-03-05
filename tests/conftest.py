"""
pytest configuration and shared fixtures for SecConfig Analyzer tests.
"""

import pytest
import os
import sys
from datetime import datetime

# Add src to path so tests can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# ─────────────────────────────────────────────
# Fixture: sample raw content strings
# ─────────────────────────────────────────────

@pytest.fixture
def vulnerable_env_content():
    return (
        "# Test config\n"
        "DATABASE_PASSWORD=admin123\n"
        "DB_USERNAME=root\n"
        "API_KEY=sk-abc123xyz789\n"
        "SECRET_KEY=mysecrettoken\n"
        "DEBUG=true\n"
        "CORS_ORIGIN=*\n"
        "CIPHER_ALGORITHM=DES\n"
        "SSL_VERIFY=false\n"
        "LOGGING_ENABLED=false\n"
        "LOG_LEVEL=DEBUG\n"
        "SESSION_TIMEOUT=0\n"
        "TESTING=true\n"
    )

@pytest.fixture
def secure_env_content():
    return (
        "# Secure config\n"
        "DATABASE_PASSWORD=${DATABASE_PASSWORD}\n"
        "DB_USERNAME=${DB_USERNAME}\n"
        "API_KEY=${API_KEY}\n"
        "SECRET_KEY=${SECRET_KEY}\n"
        "DEBUG=false\n"
        "CORS_ORIGIN=${ALLOWED_ORIGINS}\n"
        "CIPHER_ALGORITHM=AES-256-GCM\n"
        "SSL_VERIFY=true\n"
        "LOGGING_ENABLED=true\n"
        "LOG_LEVEL=WARNING\n"
        "SESSION_TIMEOUT=1800\n"
        "TESTING=false\n"
    )

@pytest.fixture
def vulnerable_yaml_content():
    return (
        "application:\n"
        "  debug: true\n"
        "  testing: true\n"
        "database:\n"
        "  password: db_password_123\n"
        "  ssl_verify: false\n"
        "security:\n"
        "  secret_key: hardcoded_secret_key\n"
        "  cors_origin: \"*\"\n"
        "  cipher_suite: DES\n"
        "logging:\n"
        "  enabled: false\n"
        "  level: DEBUG\n"
    )

@pytest.fixture
def vulnerable_json_content():
    return (
        '{\n'
        '  "app": {"debug": true, "testing": true},\n'
        '  "db": {"password": "jsonpassword123", "ssl_verify": false},\n'
        '  "security": {"cors": "*", "cipher": "MD5"},\n'
        '  "logging": {"enabled": false, "level": "DEBUG"}\n'
        '}\n'
    )

@pytest.fixture
def empty_content():
    return ""

@pytest.fixture
def comments_only_content():
    return "# Only comments\n# No real config\n"

@pytest.fixture
def malformed_yaml_content():
    return (
        "app:\n"
        "  name: test\n"
        "    bad_indent: broken\n"
        "  key: value\n"
    )

# ─────────────────────────────────────────────
# Fixture: file paths from synthetic data
# ─────────────────────────────────────────────

@pytest.fixture
def synthetic_data_dir():
    return os.path.join(
        os.path.dirname(__file__), '..', 'data', 'synthetic_configs'
    )

@pytest.fixture
def rules_dir():
    return os.path.join(
        os.path.dirname(__file__), '..', 'data', 'rules_catalog'
    )

@pytest.fixture
def templates_dir():
    return os.path.join(
        os.path.dirname(__file__), '..', 'data', 'templates_catalog'
    )
