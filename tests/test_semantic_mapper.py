"""
Unit tests for semantic mapper.
"""
import unittest
from app.utils.mapping import SemanticMapper


class TestSemanticMapper(unittest.TestCase):
    """Test cases for SemanticMapper class."""

    def test_map_concept_fortinet_to_zscaler(self):
        """Test mapping concepts from Fortinet to Zscaler."""
        # Act
        result = SemanticMapper.map_concept("address_object", "fortinet", "zscaler")
        
        # Assert
        self.assertEqual(result, "location")

    def test_map_concept_zscaler_to_fortinet(self):
        """Test mapping concepts from Zscaler to Fortinet."""
        # Act
        result = SemanticMapper.map_concept("location", "zscaler", "fortinet")
        
        # Assert
        self.assertEqual(result, "address_object")

    def test_map_concept_unknown_mapping(self):
        """Test mapping unknown concept returns original concept."""
        # Act
        result = SemanticMapper.map_concept("unknown_concept", "fortinet", "zscaler")
        
        # Assert
        self.assertEqual(result, "unknown_concept")

    def test_map_action_accept_to_block(self):
        """Test mapping action from accept to BLOCK."""
        # Act
        result = SemanticMapper.map_action("accept", "fortinet", "zscaler")
        
        # Assert
        self.assertEqual(result, "ALLOW")  # Based on our mapping

    def test_map_action_block_to_deny(self):
        """Test mapping action from BLOCK to deny."""
        # Act
        result = SemanticMapper.map_action("BLOCK", "zscaler", "fortinet")
        
        # Assert
        self.assertEqual(result, "deny")  # Based on our mapping

    def test_normalize_fortinet_policy(self):
        """Test normalizing Fortinet policy."""
        # Arrange
        policy = {
            "srcaddr": ["internal_net"],
            "dstaddr": ["external_net"],
            "service": ["HTTP"],
            "action": "accept"
        }
        
        # Act
        result = SemanticMapper.normalize_policy(policy, "fortinet")
        
        # Assert
        self.assertIn("sources", result)
        self.assertIn("destinations", result)
        self.assertIn("services", result)
        self.assertIn("action", result)
        self.assertEqual(result["sources"], ["internal_net"])
        self.assertEqual(result["destinations"], ["external_net"])
        self.assertEqual(result["services"], ["HTTP"])

    def test_normalize_zscaler_policy(self):
        """Test normalizing Zscaler policy."""
        # Arrange
        policy = {
            "locations": ["New_York_Office"],
            "departments": ["Marketing"],
            "applications": ["Facebook"],
            "action": "BLOCK"
        }
        
        # Act
        result = SemanticMapper.normalize_policy(policy, "zscaler")
        
        # Assert
        self.assertIn("sources", result)
        self.assertIn("destinations", result)
        self.assertIn("services", result)
        self.assertIn("action", result)


if __name__ == '__main__':
    unittest.main()