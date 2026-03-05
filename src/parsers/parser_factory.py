"""
Parser Factory
Returns the correct parser based on file extension.
"""
from .base_parser import BaseParser
from .env_parser import EnvParser
from .yaml_parser import YamlParser
from .json_parser import JsonParser


class UnsupportedFileTypeError(Exception):
    """Raised when an unsupported file type is provided."""
    pass


class ParserFactory:
    """
    Factory class that returns the appropriate parser for a given file type.

    Usage:
        parser = ParserFactory.get_parser("env")
        config = parser.parse(content, "app.env")
    """

    SUPPORTED_TYPES = {
        "env":  EnvParser,
        "yaml": YamlParser,
        "yml":  YamlParser,
        "json": JsonParser,
    }

    @staticmethod
    def get_parser(file_type: str) -> BaseParser:
        """
        Return the appropriate parser instance for the given file type.

        Args:
            file_type: File extension without dot (e.g. 'env', 'yaml', 'json')

        Returns:
            An instance of the appropriate parser

        Raises:
            UnsupportedFileTypeError: If the file type is not supported
        """
        file_type = file_type.lower().strip().lstrip(".")

        parser_class = ParserFactory.SUPPORTED_TYPES.get(file_type)

        if parser_class is None:
            supported = ", ".join(ParserFactory.SUPPORTED_TYPES.keys())
            raise UnsupportedFileTypeError(
                f"Unsupported file type: '{file_type}'. "
                f"Supported types: {supported}"
            )

        return parser_class()

    @staticmethod
    def get_file_type_from_name(file_name: str) -> str:
        """
        Extract file type from a filename.

        Examples:
            'app.env'    → 'env'
            'config.yml' → 'yml'
            '.env'       → 'env'
        """
        file_name = file_name.strip()

        # Handle dotfiles like '.env'
        if file_name.startswith(".") and "." not in file_name[1:]:
            return file_name[1:].lower()

        if "." in file_name:
            return file_name.rsplit(".", 1)[-1].lower()

        return file_name.lower()

    @staticmethod
    def is_supported(file_name: str) -> bool:
        """
        Check if a file is supported based on its name.

        Args:
            file_name: The filename to check

        Returns:
            True if the file type is supported
        """
        file_type = ParserFactory.get_file_type_from_name(file_name)
        return file_type in ParserFactory.SUPPORTED_TYPES

    @staticmethod
    def supported_extensions() -> list:
        """Return list of supported file extensions."""
        return list(ParserFactory.SUPPORTED_TYPES.keys())
