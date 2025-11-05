"""
Unit tests for parser factory.
"""
import unittest
from app.parsers.factory import ParserFactory
from app.parsers.fortinet_parser import FortinetParser
from app.parsers.zscaler_parser import ZscalerParser


class TestParserFactory(unittest.TestCase):
    """Test cases for ParserFactory class."""

    def test_create_fortinet_parser(self):
        """Test creation of Fortinet parser."""
        # Act
        parser = ParserFactory.create_parser("fortinet")
        
        # Assert
        self.assertIsInstance(parser, FortinetParser)

    def test_create_zscaler_parser(self):
        """Test creation of Zscaler parser."""
        # Act
        parser = ParserFactory.create_parser("zscaler")
        
        # Assert
        self.assertIsInstance(parser, ZscalerParser)

    def test_create_parser_case_insensitive(self):
        """Test creation of parser is case insensitive."""
        # Act
        parser1 = ParserFactory.create_parser("FORTINET")
        parser2 = ParserFactory.create_parser("Fortinet")
        
        # Assert
        self.assertIsInstance(parser1, FortinetParser)
        self.assertIsInstance(parser2, FortinetParser)

    def test_create_unknown_parser_raises_error(self):
        """Test creation of unknown parser raises ValueError."""
        # Act & Assert
        with self.assertRaises(ValueError) as context:
            ParserFactory.create_parser("unknown_vendor")
        
        self.assertIn("No parser registered for vendor", str(context.exception))

    def test_get_supported_vendors(self):
        """Test getting supported vendors."""
        # Act
        vendors = ParserFactory.get_supported_vendors()
        
        # Assert
        self.assertIn("fortinet", vendors)
        self.assertIn("zscaler", vendors)

    def test_register_new_parser(self):
        """Test registering a new parser."""
        # Setup
        class DummyParser:
            pass
            
        # Act
        ParserFactory.register_parser("dummy", DummyParser)
        parser = ParserFactory.create_parser("dummy")
        
        # Assert
        self.assertIsInstance(parser, DummyParser)


if __name__ == '__main__':
    unittest.main()