"""
Visualization utilities for firewall policy analysis.
"""
import logging
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend
import io
import base64
from typing import Dict, Any, List
import numpy as np

# Configure logging
logger = logging.getLogger(__name__)

class PolicyVisualizer:
    """Visualizer for firewall policy analysis results."""

    def generate_policy_count_comparison_chart(self, config_a: Dict[str, Any], config_b: Dict[str, Any]) -> str:
        """
        Generate a bar chart comparing policy counts between two firewalls.
        
        Args:
            config_a: First firewall configuration
            config_b: Second firewall configuration
            
        Returns:
            Base64 encoded PNG image
        """
        logger.info("Generating policy count comparison chart")
        try:
            # Extract policy counts
            logger.debug("Extracting policy counts")
            count_a = len(config_a.get("policies", []))
            count_b = len(config_b.get("policies", []))
            logger.info(f"Policy counts - Firewall A: {count_a}, Firewall B: {count_b}")
            
            # Create bar chart
            fig, ax = plt.subplots(figsize=(8, 6))
            firewalls = [config_a.get("vendor", "Firewall A"), config_b.get("vendor", "Firewall B")]
            counts = [count_a, count_b]
            
            bars = ax.bar(firewalls, counts, color=['#1f77b4', '#ff7f0e'])
            ax.set_ylabel('Number of Policies')
            ax.set_title('Policy Count Comparison')
            
            # Add value labels on bars
            for bar, count in zip(bars, counts):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.5, 
                       str(count), ha='center', va='bottom')
            
            # Save to base64 string
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png', bbox_inches='tight')
            img_buffer.seek(0)
            img_str = base64.b64encode(img_buffer.read()).decode()
            plt.close(fig)
            
            logger.info("Policy count comparison chart generated successfully")
            return img_str
        except Exception as e:
            logger.error(f"Error generating policy count comparison chart: {str(e)}")
            raise

    def generate_policy_action_distribution_chart(self, config: Dict[str, Any]) -> str:
        """
        Generate a pie chart showing policy action distribution.
        
        Args:
            config: Firewall configuration
            
        Returns:
            Base64 encoded PNG image
        """
        logger.info("Generating policy action distribution chart")
        try:
            policies = config.get("policies", [])
            logger.info(f"Processing {len(policies)} policies for action distribution")
            
            # Count actions
            action_counts = {}
            for policy in policies:
                action = policy.get("action", "unknown").lower()
                action_counts[action] = action_counts.get(action, 0) + 1
            
            if not action_counts:
                return ""
            
            # Create pie chart
            fig, ax = plt.subplots(figsize=(8, 6))
            actions = list(action_counts.keys())
            counts = list(action_counts.values())
            
            # Define colors
            colors = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
            
            ax.pie(counts, labels=actions, autopct='%1.1f%%', colors=colors[:len(actions)], startangle=90)
            ax.set_title('Policy Action Distribution')
            
            # Save to base64 string
            img_buffer = io.BytesIO()
            plt.savefig(img_buffer, format='png', bbox_inches='tight')
            img_buffer.seek(0)
            img_str = base64.b64encode(img_buffer.read()).decode()
            plt.close(fig)
            
            logger.info("Policy action distribution chart generated successfully")
            return img_str
        except Exception as e:
            logger.error(f"Error generating policy action distribution chart: {str(e)}")
            raise

    def generate_compliance_score_chart(self, compliance_results: Dict[str, Any]) -> str:
        """
        Generate a bar chart showing compliance scores for different standards.
        
        Args:
            compliance_results: Compliance check results
            
        Returns:
            Base64 encoded PNG image
        """
        standards = compliance_results.get("standards", {})
        
        if not standards:
            return ""
        
        # Extract standard names and scores
        standard_names = list(standards.keys())
        scores = [standards[standard].get("score", 0) for standard in standard_names]
        
        # Create bar chart
        fig, ax = plt.subplots(figsize=(10, 6))
        bars = ax.bar(standard_names, scores, color='#2ca02c')
        ax.set_ylabel('Compliance Score (%)')
        ax.set_xlabel('Standards')
        ax.set_title('Compliance Score by Standard')
        ax.set_ylim(0, 100)
        
        # Add value labels on bars
        for bar, score in zip(bars, scores):
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 1, 
                   f'{score:.1f}%', ha='center', va='bottom')
        
        # Save to base64 string
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', bbox_inches='tight')
        img_buffer.seek(0)
        img_str = base64.b64encode(img_buffer.read()).decode()
        plt.close(fig)
        
        return img_str

    def generate_policy_overlap_heatmap(self, config_a: Dict[str, Any], config_b: Dict[str, Any]) -> str:
        """
        Generate a heatmap showing policy overlaps between two firewalls.
        
        Args:
            config_a: First firewall configuration
            config_b: Second firewall configuration
            
        Returns:
            Base64 encoded PNG image
        """
        # This is a simplified implementation
        # In a real implementation, this would analyze actual policy overlaps
        
        # Create a simple heatmap
        fig, ax = plt.subplots(figsize=(8, 6))
        
        # Sample data for demonstration
        data = np.random.rand(5, 5)
        im = ax.imshow(data, cmap='Blues')
        
        # Add labels
        ax.set_xticks(np.arange(5))
        ax.set_yticks(np.arange(5))
        ax.set_xticklabels([f'Policy {i+1}' for i in range(5)])
        ax.set_yticklabels([f'Policy {i+1}' for i in range(5)])
        
        ax.set_title('Policy Overlap Analysis (Sample)')
        fig.tight_layout()
        
        # Save to base64 string
        img_buffer = io.BytesIO()
        plt.savefig(img_buffer, format='png', bbox_inches='tight')
        img_buffer.seek(0)
        img_str = base64.b64encode(img_buffer.read()).decode()
        plt.close(fig)
        
        return img_str