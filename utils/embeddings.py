"""
Embedding utilities for semantic policy analysis.
"""
import numpy as np
from typing import List, Dict, Any
from app.vendors.abstract import NormalizedPolicy
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


class PolicyEmbedder:
    """Utility class for creating embeddings of firewall policies."""
    
    def __init__(self):
        """Initialize the policy embedder."""
        self.vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words=None,
            lowercase=True,
            token_pattern=r'\b[a-zA-Z0-9_/*\-:.]+\b'
        )
        self.is_fitted = False

    def create_policy_text_representation(self, policy: NormalizedPolicy) -> str:
        """
        Create a text representation of a policy for embedding.
        
        Args:
            policy: Normalized policy
            
        Returns:
            Text representation of the policy
        """
        # Create a comprehensive text representation that captures the policy's semantics
        components = []
        
        # Add policy name and comments
        if policy.name:
            components.append(f"name:{policy.name}")
        if policy.comments:
            components.append(f"comments:{policy.comments}")
            
        # Add source information
        if policy.source_zones:
            components.append(f"source_zones:{'|'.join(policy.source_zones)}")
        if policy.source_addresses:
            components.append(f"source_addresses:{'|'.join(policy.source_addresses)}")
            
        # Add destination information
        if policy.destination_zones:
            components.append(f"destination_zones:{'|'.join(policy.destination_zones)}")
        if policy.destination_addresses:
            components.append(f"destination_addresses:{'|'.join(policy.destination_addresses)}")
            
        # Add services
        if policy.services:
            components.append(f"services:{'|'.join(policy.services)}")
            
        # Add action
        components.append(f"action:{policy.action}")
        
        # Add other attributes
        if policy.enabled:
            components.append("enabled")
        if policy.logging:
            components.append("logging")
        if policy.schedule and policy.schedule != "always":
            components.append(f"schedule:{policy.schedule}")
            
        return " ".join(components)

    def create_policy_embeddings(self, policies: List[NormalizedPolicy]) -> np.ndarray:
        """
        Create embeddings for a list of policies.
        
        Args:
            policies: List of normalized policies
            
        Returns:
            Array of policy embeddings
        """
        # Create text representations
        policy_texts = [self.create_policy_text_representation(policy) for policy in policies]
        
        # Fit vectorizer if not already fitted
        if not self.is_fitted:
            self.vectorizer.fit(policy_texts)
            self.is_fitted = True
            
        # Transform texts to embeddings
        embeddings = self.vectorizer.transform(policy_texts)
        return embeddings.toarray()

    def calculate_semantic_similarity(self, policy1: NormalizedPolicy, policy2: NormalizedPolicy) -> float:
        """
        Calculate semantic similarity between two policies using embeddings.
        
        Args:
            policy1: First normalized policy
            policy2: Second normalized policy
            
        Returns:
            Similarity score between 0 and 1
        """
        # Create text representations
        text1 = self.create_policy_text_representation(policy1)
        text2 = self.create_policy_text_representation(policy2)
        
        # Fit vectorizer if not already fitted
        if not self.is_fitted:
            self.vectorizer.fit([text1, text2])
            self.is_fitted = True
            
        # Transform to embeddings
        embeddings = self.vectorizer.transform([text1, text2])
        
        # Calculate cosine similarity
        similarity = cosine_similarity(embeddings[0], embeddings[1])[0][0]
        return float(similarity)

    def calculate_batch_similarity(self, policies1: List[NormalizedPolicy], policies2: List[NormalizedPolicy]) -> np.ndarray:
        """
        Calculate similarity matrix between two sets of policies.
        
        Args:
            policies1: First list of normalized policies
            policies2: Second list of normalized policies
            
        Returns:
            Similarity matrix where element (i,j) is similarity between policies1[i] and policies2[j]
        """
        # Create text representations
        texts1 = [self.create_policy_text_representation(policy) for policy in policies1]
        texts2 = [self.create_policy_text_representation(policy) for policy in policies2]
        
        # Fit vectorizer if not already fitted
        all_texts = texts1 + texts2
        if not self.is_fitted:
            self.vectorizer.fit(all_texts)
            self.is_fitted = True
            
        # Transform to embeddings
        embeddings1 = self.vectorizer.transform(texts1)
        embeddings2 = self.vectorizer.transform(texts2)
        
        # Calculate cosine similarity matrix
        similarity_matrix = cosine_similarity(embeddings1, embeddings2)
        return similarity_matrix


class AdvancedPolicyEmbedder(PolicyEmbedder):
    """Advanced policy embedder with enhanced semantic understanding."""
    
    def __init__(self):
        """Initialize the advanced policy embedder."""
        super().__init__()
        # Extended vocabulary for security domain terms
        self.security_terms = [
            # Actions
            'allow', 'permit', 'accept', 'deny', 'reject', 'drop', 'block', 'redirect',
            # Protocols
            'tcp', 'udp', 'icmp', 'http', 'https', 'ftp', 'ssh', 'dns', 'smtp', 'pop3',
            # Common services
            'web', 'email', 'database', 'file', 'application', 'api', 'service',
            # Network zones
            'internal', 'external', 'dmz', 'public', 'private', 'guest', 'management',
            # Security levels
            'high', 'medium', 'low', 'critical', 'restricted', 'trusted', 'untrusted',
            # Time-related
            'always', 'never', 'business_hours', 'after_hours', 'weekend',
            # Logging
            'log', 'audit', 'monitor', 'record',
            # Common applications
            'facebook', 'twitter', 'linkedin', 'youtube', 'instagram', 'netflix',
            'dropbox', 'google', 'microsoft', 'amazon', 'salesforce'
        ]

    def create_policy_text_representation(self, policy: NormalizedPolicy) -> str:
        """
        Create an enhanced text representation of a policy for embedding.
        
        Args:
            policy: Normalized policy
            
        Returns:
            Enhanced text representation of the policy
        """
        # Create a comprehensive text representation with security domain knowledge
        components = []
        
        # Add policy name and comments with enhanced processing
        if policy.name:
            components.append(f"name_{policy.name.lower()}")
        if policy.comments:
            components.append(f"comments_{policy.comments.lower()}")
            
        # Add source information with semantic enhancement
        if policy.source_zones:
            for zone in policy.source_zones:
                components.append(f"source_zone_{zone.lower()}")
        if policy.source_addresses:
            for addr in policy.source_addresses:
                components.append(f"source_addr_{addr.lower()}")
            
        # Add destination information with semantic enhancement
        if policy.destination_zones:
            for zone in policy.destination_zones:
                components.append(f"dest_zone_{zone.lower()}")
        if policy.destination_addresses:
            for addr in policy.destination_addresses:
                components.append(f"dest_addr_{addr.lower()}")
            
        # Add services with semantic enhancement
        if policy.services:
            for service in policy.services:
                components.append(f"service_{service.lower()}")
            
        # Add action with semantic enhancement
        components.append(f"action_{policy.action.lower()}")
        
        # Add other attributes with semantic enhancement
        if policy.enabled:
            components.append("state_enabled")
        else:
            components.append("state_disabled")
            
        if policy.logging:
            components.append("logging_enabled")
            
        if policy.schedule and policy.schedule != "always":
            components.append(f"schedule_{policy.schedule.lower()}")
            
        # Add security domain terms that might be relevant
        text = " ".join(components)
        return text + " " + " ".join(self.security_terms)