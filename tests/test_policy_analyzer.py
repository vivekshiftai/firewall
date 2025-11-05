"""
Unit tests for policy analyzer.
"""
import unittest
from app.analyzers.policy_analyzer import PolicyAnalyzer
from app.models.base import FirewallConfig


class TestPolicyAnalyzer(unittest.TestCase):
    """Test cases for PolicyAnalyzer class."""

    def setUp(self):
        """Set up test fixtures."""
        self.analyzer = PolicyAnalyzer()
        self.sample_config = FirewallConfig(
            id="test-firewall",
            vendor="fortinet",
            version="v6.4.5",
            policies=[
                {
                    "id": 1,
                    "name": "Allow_HTTP",
                    "srcaddr": ["internal_net"],
                    "dstaddr": ["external_net"],
                    "service": ["HTTP"],
                    "action": "accept"
                },
                {
                    "id": 2,
                    "name": "Deny_All",
                    "srcaddr": ["all"],
                    "dstaddr": ["all"],
                    "service": ["ALL"],
                    "action": "deny"
                }
            ],
            objects=[
                {
                    "name": "internal_net",
                    "type": "ipmask",
                    "subnet": "192.168.1.0/24"
                }
            ]
        )

    def test_analyze_single_firewall(self):
        """Test analysis of single firewall configuration."""
        # Act
        result = self.analyzer.analyze_single_firewall(self.sample_config)
        
        # Assert
        self.assertIsInstance(result, dict)
        self.assertIn("firewall_id", result)
        self.assertIn("vendor", result)
        self.assertIn("inconsistencies", result)
        self.assertIn("recommendations", result)
        self.assertIn("summary", result)
        self.assertEqual(result["firewall_id"], "test-firewall")

    def test_compare_firewalls(self):
        """Test comparison of two firewall configurations."""
        # Arrange
        config_a = self.sample_config
        config_b = FirewallConfig(
            id="test-firewall-2",
            vendor="zscaler",
            version="20.8.0",
            policies=[
                {
                    "id": "1001",
                    "name": "Block_Social_Media",
                    "locations": ["New_York_Office"],
                    "applications": ["Facebook"],
                    "action": "BLOCK"
                }
            ],
            objects=[]
        )
        
        # Act
        result = self.analyzer.compare_firewalls(config_a, config_b)
        
        # Assert
        self.assertIsInstance(result, dict)
        self.assertIn("firewall_a_id", result)
        self.assertIn("firewall_b_id", result)
        self.assertIn("parity_matrix", result)
        self.assertIn("differences", result)
        self.assertIn("recommendations", result)
        self.assertIn("compliance_gaps", result)

    def test_check_compliance(self):
        """Test compliance checking."""
        # Act
        result = self.analyzer.check_compliance(self.sample_config, ["GDPR", "ISO27001"])
        
        # Assert
        self.assertIsInstance(result, dict)
        self.assertIn("firewall_id", result)
        self.assertIn("standards", result)
        self.assertIn("overall_compliance", result)
        self.assertEqual(result["firewall_id"], "test-firewall")

    def test_find_inconsistencies_no_duplicates(self):
        """Test finding inconsistencies with no duplicates."""
        # Act
        result = self.analyzer.analyze_single_firewall(self.sample_config)
        
        # Assert
        self.assertEqual(len(result["inconsistencies"]), 0)

    def test_calculate_compliance_score(self):
        """Test compliance score calculation."""
        # Act
        result = self.analyzer.analyze_single_firewall(self.sample_config)
        
        # Assert
        self.assertIn("summary", result)
        self.assertIn("compliance_score", result["summary"])
        self.assertIsInstance(result["summary"]["compliance_score"], float)
        self.assertGreaterEqual(result["summary"]["compliance_score"], 0.0)
        self.assertLessEqual(result["summary"]["compliance_score"], 100.0)


if __name__ == '__main__':
    unittest.main()