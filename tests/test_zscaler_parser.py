"""
Unit tests for Zscaler parser.
"""
import unittest
from app.parsers.zscaler_parser import ZscalerParser
from app.models.base import FirewallConfig


class TestZscalerParser(unittest.TestCase):
    """Test cases for ZscalerParser class."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = ZscalerParser()
        self.sample_config = {
            "cloud": "zscaler",
            "version": "20.8.0",
            "rules": [
                {
                    "id": "1001",
                    "name": "Block_Social_Media",
                    "locations": ["New_York_Office"],
                    "departments": ["Marketing"],
                    "users": ["all"],
                    "applications": ["Facebook", "Twitter"],
                    "action": "BLOCK",
                    "enabled": True
                }
            ],
            "locations": [
                {
                    "id": "loc-1",
                    "name": "New_York_Office",
                    "ipAddresses": ["192.168.1.0/24"]
                }
            ],
            "user_groups": [
                {
                    "id": "ug-1",
                    "name": "Marketing",
                    "users": ["user1@example.com", "user2@example.com"]
                }
            ]
        }

    def test_parse_valid_config(self):
        """Test parsing of valid Zscaler configuration."""
        # Act
        result = self.parser.parse(self.sample_config)
        
        # Assert
        self.assertIsInstance(result, FirewallConfig)
        self.assertEqual(result.id, "zscaler")
        self.assertEqual(result.vendor, "zscaler")
        self.assertEqual(result.version, "20.8.0")
        self.assertEqual(len(result.policies), 1)
        self.assertEqual(len(result.objects), 3)

    def test_validate_config(self):
        """Test validation of parsed configuration."""
        # Arrange
        config = FirewallConfig(
            id="zscaler-test",
            vendor="zscaler",
            version="20.8.0",
            policies=[],
            objects=[]
        )
        
        # Act
        is_valid = self.parser.validate_config(config)
        
        # Assert
        self.assertTrue(is_valid)

    def test_validate_invalid_vendor(self):
        """Test validation fails with invalid vendor."""
        # Arrange
        config = FirewallConfig(
            id="test",
            vendor="fortinet",
            version="20.8.0",
            policies=[],
            objects=[]
        )
        
        # Act
        is_valid = self.parser.validate_config(config)
        
        # Assert
        self.assertFalse(is_valid)

    def test_parse_empty_config(self):
        """Test parsing of empty configuration."""
        # Arrange
        empty_config = {
            "cloud": "zscaler"
        }
        
        # Act
        result = self.parser.parse(empty_config)
        
        # Assert
        self.assertIsInstance(result, FirewallConfig)
        self.assertEqual(result.id, "zscaler")
        self.assertEqual(result.vendor, "zscaler")
        self.assertEqual(len(result.policies), 0)
        self.assertEqual(len(result.objects), 0)


if __name__ == '__main__':
    unittest.main()