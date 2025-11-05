"""
Unit tests for Fortinet parser.
"""
import unittest
import json
from app.parsers.fortinet_parser import FortinetParser
from app.models.base import FirewallConfig


class TestFortinetParser(unittest.TestCase):
    """Test cases for FortinetParser class."""

    def setUp(self):
        """Set up test fixtures."""
        self.parser = FortinetParser()
        self.sample_config = {
            "system": {
                "global": {
                    "hostname": "FGT_TEST"
                }
            },
            "version": "v6.4.5",
            "firewall": {
                "policy": {
                    "1": {
                        "name": "Allow_HTTP",
                        "srcintf": [{"name": "internal"}],
                        "dstintf": [{"name": "external"}],
                        "srcaddr": [{"name": "all"}],
                        "dstaddr": [{"name": "all"}],
                        "service": [{"name": "HTTP"}],
                        "action": "accept",
                        "status": "enable",
                        "schedule": "always"
                    }
                },
                "address": {
                    "all": {
                        "type": "ipmask",
                        "subnet": "0.0.0.0/0"
                    }
                },
                "service": {
                    "HTTP": {
                        "protocol": "TCP/UDP/SCTP",
                        "tcp-portrange": "80"
                    }
                }
            }
        }

    def test_parse_valid_config(self):
        """Test parsing of valid Fortinet configuration."""
        # Act
        result = self.parser.parse(self.sample_config)
        
        # Assert
        self.assertIsInstance(result, FirewallConfig)
        self.assertEqual(result.id, "FGT_TEST")
        self.assertEqual(result.vendor, "fortinet")
        self.assertEqual(result.version, "v6.4.5")
        self.assertEqual(len(result.policies), 1)
        self.assertEqual(len(result.objects), 2)

    def test_validate_config(self):
        """Test validation of parsed configuration."""
        # Arrange
        config = FirewallConfig(
            id="test",
            vendor="fortinet",
            version="v6.4.5",
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
            vendor="cisco",
            version="v6.4.5",
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
            "system": {},
            "firewall": {}
        }
        
        # Act
        result = self.parser.parse(empty_config)
        
        # Assert
        self.assertIsInstance(result, FirewallConfig)
        self.assertEqual(result.id, "unknown")
        self.assertEqual(result.vendor, "fortinet")
        self.assertEqual(len(result.policies), 0)
        self.assertEqual(len(result.objects), 0)


if __name__ == '__main__':
    unittest.main()