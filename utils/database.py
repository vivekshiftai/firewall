"""
Database utilities for storing analysis results.
"""
import sqlite3
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
import os


class AnalysisDatabase:
    """SQLite database for storing firewall analysis results."""

    def __init__(self, db_path: str = "analysis_results.db"):
        """Initialize the database."""
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize the database schema."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create analysis results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS analysis_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                analysis_id TEXT UNIQUE NOT NULL,
                firewall_id TEXT,
                vendor TEXT,
                analysis_type TEXT NOT NULL,
                results TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create comparison results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS comparison_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                comparison_id TEXT UNIQUE NOT NULL,
                firewall_a_id TEXT NOT NULL,
                firewall_b_id TEXT NOT NULL,
                vendor_a TEXT NOT NULL,
                vendor_b TEXT NOT NULL,
                results TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create compliance results table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS compliance_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                compliance_id TEXT UNIQUE NOT NULL,
                firewall_id TEXT NOT NULL,
                vendor TEXT NOT NULL,
                standards TEXT NOT NULL,
                results TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()

    def save_analysis_result(self, analysis_id: str, firewall_id: str, vendor: str, 
                           analysis_type: str, results: Dict[str, Any]) -> bool:
        """
        Save a single firewall analysis result.
        
        Args:
            analysis_id: Unique identifier for this analysis
            firewall_id: Firewall identifier
            vendor: Firewall vendor
            analysis_type: Type of analysis (single, compliance, etc.)
            results: Analysis results
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO analysis_results 
                (analysis_id, firewall_id, vendor, analysis_type, results)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                analysis_id,
                firewall_id,
                vendor,
                analysis_type,
                json.dumps(results)
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error saving analysis result: {str(e)}")
            return False

    def save_comparison_result(self, comparison_id: str, firewall_a_id: str, firewall_b_id: str,
                             vendor_a: str, vendor_b: str, results: Dict[str, Any]) -> bool:
        """
        Save a firewall comparison result.
        
        Args:
            comparison_id: Unique identifier for this comparison
            firewall_a_id: First firewall identifier
            firewall_b_id: Second firewall identifier
            vendor_a: First firewall vendor
            vendor_b: Second firewall vendor
            results: Comparison results
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO comparison_results 
                (comparison_id, firewall_a_id, firewall_b_id, vendor_a, vendor_b, results)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                comparison_id,
                firewall_a_id,
                firewall_b_id,
                vendor_a,
                vendor_b,
                json.dumps(results)
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error saving comparison result: {str(e)}")
            return False

    def save_compliance_result(self, compliance_id: str, firewall_id: str, vendor: str,
                             standards: List[str], results: Dict[str, Any]) -> bool:
        """
        Save a compliance check result.
        
        Args:
            compliance_id: Unique identifier for this compliance check
            firewall_id: Firewall identifier
            vendor: Firewall vendor
            standards: List of standards checked
            results: Compliance results
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO compliance_results 
                (compliance_id, firewall_id, vendor, standards, results)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                compliance_id,
                firewall_id,
                vendor,
                json.dumps(standards),
                json.dumps(results)
            ))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error saving compliance result: {str(e)}")
            return False

    def get_analysis_result(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a single firewall analysis result.
        
        Args:
            analysis_id: Analysis identifier
            
        Returns:
            Analysis result or None if not found
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM analysis_results WHERE analysis_id = ?
            ''', (analysis_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "id": row[0],
                    "analysis_id": row[1],
                    "firewall_id": row[2],
                    "vendor": row[3],
                    "analysis_type": row[4],
                    "results": json.loads(row[5]),
                    "created_at": row[6],
                    "updated_at": row[7]
                }
            return None
        except Exception as e:
            print(f"Error retrieving analysis result: {str(e)}")
            return None

    def get_comparison_result(self, comparison_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a firewall comparison result.
        
        Args:
            comparison_id: Comparison identifier
            
        Returns:
            Comparison result or None if not found
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM comparison_results WHERE comparison_id = ?
            ''', (comparison_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "id": row[0],
                    "comparison_id": row[1],
                    "firewall_a_id": row[2],
                    "firewall_b_id": row[3],
                    "vendor_a": row[4],
                    "vendor_b": row[5],
                    "results": json.loads(row[6]),
                    "created_at": row[7]
                }
            return None
        except Exception as e:
            print(f"Error retrieving comparison result: {str(e)}")
            return None

    def get_compliance_result(self, compliance_id: str) -> Optional[Dict[str, Any]]:
        """
        Retrieve a compliance check result.
        
        Args:
            compliance_id: Compliance check identifier
            
        Returns:
            Compliance result or None if not found
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM compliance_results WHERE compliance_id = ?
            ''', (compliance_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    "id": row[0],
                    "compliance_id": row[1],
                    "firewall_id": row[2],
                    "vendor": row[3],
                    "standards": json.loads(row[4]),
                    "results": json.loads(row[5]),
                    "created_at": row[6]
                }
            return None
        except Exception as e:
            print(f"Error retrieving compliance result: {str(e)}")
            return None

    def get_recent_analyses(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get recent analysis results.
        
        Args:
            limit: Maximum number of results to return
            
        Returns:
            List of recent analysis results
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM analysis_results 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            
            rows = cursor.fetchall()
            conn.close()
            
            results = []
            for row in rows:
                results.append({
                    "id": row[0],
                    "analysis_id": row[1],
                    "firewall_id": row[2],
                    "vendor": row[3],
                    "analysis_type": row[4],
                    "results": json.loads(row[5]),
                    "created_at": row[6],
                    "updated_at": row[7]
                })
                
            return results
        except Exception as e:
            print(f"Error retrieving recent analyses: {str(e)}")
            return []

    def delete_analysis_result(self, analysis_id: str) -> bool:
        """
        Delete an analysis result.
        
        Args:
            analysis_id: Analysis identifier
            
        Returns:
            True if successful, False otherwise
        """
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                DELETE FROM analysis_results WHERE analysis_id = ?
            ''', (analysis_id,))
            
            conn.commit()
            conn.close()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"Error deleting analysis result: {str(e)}")
            return False