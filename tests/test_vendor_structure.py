"""
Unit tests for the new vendor structure.
"""
import unittest
import sys
import os

# Add the project root to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.vendors.fortinet.parser import FortinetConfigParser
from app.vendors.fortinet.normalizer import FortinetPolicyNormalizer
from app.vendors.zscaler.parser import ZscalerConfigParser
from app.vendors.zscaler.normalizer import ZscalerPolicyNormalizer
from app.vendors.abstract import ParsedConfig


class TestVendorStructure(unittest.TestCase):
    """Test cases for the new vendor structure."""

    def test_fortinet_parser_import(self):
        """Test that Fortinet parser can be imported."""
        parser = FortinetConfigParser()
        self.assertIsInstance(parser, FortinetConfigParser)

    def test_zscaler_parser_import(self):
        """Test that Zscaler parser can be imported."""
        parser = ZscalerConfigParser()
        self.assertIsInstance(parser, ZscalerConfigParser)

    def test_fortinet_normalizer_import(self):
        """Test that Fortinet normalizer can be imported."""
        # Create a minimal parsed config for testing
        config = ParsedConfig(vendor="fortinet", version="test")
        normalizer = FortinetPolicyNormalizer(config)
        self.assertIsInstance(normalizer, FortinetPolicyNormalizer)

    def test_zscaler_normalizer_import(self):
        """Test that Zscaler normalizer can be imported."""
        # Create a minimal parsed config for testing
        config = ParsedConfig(vendor="zscaler", version="test")
        normalizer = ZscalerPolicyNormalizer(config)
        self.assertIsInstance(normalizer, ZscalerPolicyNormalizer)

    def test_abstract_classes_exist(self):
        """Test that abstract classes can be imported."""
        # This test just verifies the imports work
        from app.vendors.abstract import AbstractVendorParser, AbstractFirewallAnalyzer, AbstractPolicyNormalizer
        from app.vendors.abstract import ParsedConfig, NormalizedPolicy, PolicyInconsistency
        
        # Verify the classes exist
        self.assertTrue(hasattr(AbstractVendorParser, 'parse_config'))
        self.assertTrue(hasattr(AbstractFirewallAnalyzer, 'analyze'))
        self.assertTrue(hasattr(AbstractPolicyNormalizer, 'normalize_policies'))


if __name__ == '__main__':
    unittest.main()