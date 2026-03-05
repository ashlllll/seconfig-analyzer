"""
Identification Service
NIST CSF Function: IDENTIFY
Discovers and catalogues assets within a configuration file.
"""
import re
from typing import Any, Dict, List

from ..models.config_model import ConfigFile


# Patterns for identifying sensitive asset types
CREDENTIAL_KEYS = re.compile(
    r'(?i)(password|passwd|pwd|secret|token|api_key|apikey|'
    r'auth|credential|private_key|access_key)'
)

ENCRYPTION_KEYS = re.compile(
    r'(?i)(encrypt|decrypt|cipher|ssl|tls|cert|key_size|'
    r'algorithm|hash|crypto)'
)

DATABASE_KEYS = re.compile(
    r'(?i)(database|db_|mongo|postgres|mysql|redis|sqlite|'
    r'connection_string|db_url)'
)

NETWORK_KEYS = re.compile(
    r'(?i)(host|port|bind|listen|cors|url|endpoint|'
    r'webhook|callback|api_url|base_url)'
)

SECURITY_SETTING_KEYS = re.compile(
    r'(?i)(debug|log|audit|session|cookie|csrf|'
    r'allowed_hosts|security|hsts|xss|frame)'
)


class IdentificationService:
    """
    NIST IDENTIFY — Discovers assets and sensitive parameters
    in a configuration file.

    This helps establish context before the Red Team analysis,
    giving users visibility into what is being protected.
    """

    def identify_assets(self, config: ConfigFile) -> Dict[str, List[Dict]]:
        """
        Scan a config file and categorise all identified assets.

        Args:
            config: Parsed ConfigFile object

        Returns:
            Dictionary of asset categories → list of asset details
        """
        assets: Dict[str, List[Dict]] = {
            "credentials":          [],
            "encryption_settings":  [],
            "database_connections": [],
            "network_settings":     [],
            "security_settings":    [],
            "other":                [],
        }

        # Use flat key-value pairs for scanning
        flat = self._get_flat_pairs(config)

        for key, value in flat.items():
            asset = self._build_asset(key, value, config)
            category = self._classify(key)
            assets[category].append(asset)

        return assets

    def get_asset_summary(self, assets: Dict[str, List[Dict]]) -> Dict[str, int]:
        """
        Return a count summary of identified assets by category.

        Args:
            assets: Result of identify_assets()

        Returns:
            Dictionary of category → count
        """
        return {category: len(items) for category, items in assets.items()}

    def get_sensitive_keys(self, config: ConfigFile) -> List[str]:
        """
        Return a list of keys that appear to hold sensitive values.

        Args:
            config: Parsed ConfigFile object

        Returns:
            List of sensitive key names
        """
        flat = self._get_flat_pairs(config)
        sensitive = []

        for key in flat:
            if CREDENTIAL_KEYS.search(key) or ENCRYPTION_KEYS.search(key):
                sensitive.append(key)

        return sensitive

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _get_flat_pairs(self, config: ConfigFile) -> Dict[str, Any]:
        """Extract flat key-value pairs from the config."""
        content = config.parsed_content

        # Use pre-flattened version if available (YAML/JSON)
        if "_flat" in content:
            return {
                k: v for k, v in content["_flat"].items()
                if not k.startswith("_")
            }

        # For .env files, parsed_content is already flat
        return {k: v for k, v in content.items() if not k.startswith("_")}

    def _classify(self, key: str) -> str:
        """Classify a key into an asset category."""
        if CREDENTIAL_KEYS.search(key):
            return "credentials"
        elif ENCRYPTION_KEYS.search(key):
            return "encryption_settings"
        elif DATABASE_KEYS.search(key):
            return "database_connections"
        elif NETWORK_KEYS.search(key):
            return "network_settings"
        elif SECURITY_SETTING_KEYS.search(key):
            return "security_settings"
        else:
            return "other"

    def _build_asset(self, key: str, value: Any, config: ConfigFile) -> Dict:
        """Build an asset descriptor dictionary."""
        str_value = str(value) if value is not None else ""
        is_sensitive = bool(CREDENTIAL_KEYS.search(key))

        return {
            "key": key,
            "value_preview": self._mask_if_sensitive(str_value, is_sensitive),
            "is_sensitive": is_sensitive,
            "file": config.file_name,
        }

    def _mask_if_sensitive(self, value: str, is_sensitive: bool) -> str:
        """Mask sensitive values in previews."""
        if not is_sensitive or not value:
            return value
        if len(value) <= 4:
            return "****"
        return value[:2] + "****" + value[-2:]
