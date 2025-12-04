import re
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple, Any

class PIIDetector:
    """
    Detects Personally Identifiable Information (PII) in datasets using
    pattern-based detection and column name heuristics.
    """
    
    def __init__(self):
        # PII patterns using regular expressions
        self.pii_patterns = {
            'EMAIL': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'PHONE': r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
            'SSN': r'\b\d{3}-\d{2}-\d{4}\b',
            'CREDIT_CARD': r'\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{13,19}\b',
            'IP_ADDRESS': r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'URL': r'https?://(?:www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b(?:[-a-zA-Z0-9()@:%_\+.~#?&/=]*)',
            'DATE_OF_BIRTH': r'\b\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b',
            'NATIONAL_ID': r'\b[A-Z0-9]{8,12}\b',
            'GPS_COORDINATES': r'[-+]?\d{1,3}\.\d+,\s*[-+]?\d{1,3}\.\d+',
            'IBAN': r'\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b',
            'ADDRESS': r'\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln)',
        }
        
        # Column name keywords for heuristic detection
        self.column_keywords = {
            'EMAIL': ['email', 'e-mail', 'mail', 'email_address', 'e_mail'],
            'PHONE': ['phone', 'telephone', 'mobile', 'cell', 'contact_number', 'phone_num', 'phone_number'],
            'NAME': ['name', 'firstname', 'lastname', 'first_name', 'last_name', 'full_name', 'username', 'patient_name', 'customer_name', 'employee_name'],
            'ID': ['patient_id', 'customer_id', 'employee_id', 'user_id', 'person_id', 'id_number', 'national_id'],
            'DOB': ['dob', 'birth', 'birthdate', 'date_of_birth', 'birthday', 'birth_date'],
            'ADDRESS': ['address', 'street', 'location', 'residence', 'home_address', 'street_address', 'physical_address'],
            'SSN': ['ssn', 'social_security', 'social_security_number'],
            'CREDIT_CARD': ['credit_card', 'cc', 'card_number', 'creditcard', 'card_num'],
            'GENDER': ['gender', 'sex'],
            'AGE': ['age'],
            'SALARY': ['salary', 'income', 'wage', 'compensation', 'pay'],
            'MEDICAL': ['medical_condition', 'diagnosis', 'medication', 'blood_type', 'medical', 'condition', 'disease', 'illness'],
        }
        
        # Impact scores for each PII type (1-5 scale)
        self.impact_scores = {
            'SSN': 5,
            'CREDIT_CARD': 5,
            'NATIONAL_ID': 5,
            'MEDICAL': 5,
            'EMAIL': 4,
            'PHONE': 4,
            'ADDRESS': 4,
            'GPS_COORDINATES': 4,
            'IBAN': 4,
            'DATE_OF_BIRTH': 3,
            'DOB': 3,
            'NAME': 3,
            'SALARY': 3,
            'ID': 2,
            'AGE': 2,
            'GENDER': 2,
            'IP_ADDRESS': 2,
            'URL': 1,
        }
    
    def detect_pattern_based(self, column_data: pd.Series) -> Tuple[str, float]:
        """
        Detect PII using pattern-based matching with regular expressions.
        
        Args:
            column_data: Pandas Series containing column data
            
        Returns:
            Tuple of (PII_TYPE, confidence_score)
        """
        # Skip non-string columns
        if column_data.dtype not in ['object', 'string']:
            return None, 0.0
        
        # Convert to string and remove NaN values
        string_data = column_data.dropna().astype(str)
        
        if len(string_data) == 0:
            return None, 0.0
        
        # Calculate average length of values
        avg_length = string_data.str.len().mean()
        
        # If average length is very long (>500 chars), it's likely essay/description text
        # These columns may contain PII mentions but aren't PII columns themselves
        if avg_length > 500:
            return None, 0.0
        
        # Test each pattern
        pattern_matches = {}
        for pii_type, pattern in self.pii_patterns.items():
            try:
                matches = string_data.str.contains(pattern, regex=True, na=False).sum()
                match_ratio = matches / len(string_data)
                
                # For shorter text (likely actual PII fields), also check content density
                if match_ratio > 0.3:  # If pattern matches
                    # Sample first non-null value to check density
                    sample = string_data.iloc[0] if len(string_data) > 0 else ""
                    
                    # If the matched pattern is a small part of much longer text, skip it
                    if len(sample) > 200:  # Long text field
                        continue
                    
                    pattern_matches[pii_type] = match_ratio
            except:
                continue
        
        # Find best match with priority handling
        if pattern_matches:
            # Priority order: More specific patterns should win over generic ones
            # Credit cards are longer and more specific than phone numbers
            priority_order = ['CREDIT_CARD', 'SSN', 'IBAN', 'EMAIL', 'PHONE', 'IP_ADDRESS', 
                            'GPS_COORDINATES', 'DATE_OF_BIRTH', 'NATIONAL_ID', 'ADDRESS', 'URL']
            
            # Check high-priority patterns first
            for pii_type in priority_order:
                if pii_type in pattern_matches and pattern_matches[pii_type] > 0.5:
                    return pii_type, pattern_matches[pii_type]
            
            # If no high-confidence high-priority match, use best match
            best_match = max(pattern_matches.items(), key=lambda x: x[1])
            if best_match[1] > 0.5:
                return best_match[0], best_match[1]
        
        return None, 0.0
    
    def detect_column_name_heuristic(self, column_name: str) -> Tuple[str, float]:
        """
        Detect PII using column name heuristics.
        
        Args:
            column_name: Name of the column
            
        Returns:
            Tuple of (PII_TYPE, confidence_score)
        """
        column_name_lower = column_name.lower().strip()
        
        # Exclude common non-PII column names
        non_pii_keywords = ['essay', 'description', 'comment', 'notes', 'text', 'content', 
                           'body', 'message', 'post', 'article', 'paragraph', 'statement',
                           'summary', 'review', 'feedback', 'provider', 'company', 'organization',
                           'department', 'title', 'category', 'type', 'status', 'role']
        
        for keyword in non_pii_keywords:
            if keyword == column_name_lower or f'_{keyword}' in column_name_lower or f'{keyword}_' in column_name_lower:
                return None, 0.0
        
        # Sort by keyword length (longest first) to avoid partial matches
        # e.g., check for "employee_id" before just "id"
        sorted_items = []
        for pii_type, keywords in self.column_keywords.items():
            for keyword in keywords:
                sorted_items.append((pii_type, keyword))
        
        # Sort by keyword length descending
        sorted_items.sort(key=lambda x: len(x[1]), reverse=True)
        
        for pii_type, keyword in sorted_items:
            if keyword in column_name_lower:
                # Exact match gets higher confidence
                if keyword == column_name_lower:
                    return pii_type, 0.9
                # Check if it's a word boundary match (not part of another word)
                elif f'_{keyword}' in column_name_lower or f'{keyword}_' in column_name_lower:
                    return pii_type, 0.8
                elif keyword == column_name_lower.split('_')[-1] or keyword == column_name_lower.split('_')[0]:
                    return pii_type, 0.7
        
        return None, 0.0
    
    def calculate_uniqueness(self, column_data: pd.Series) -> float:
        """
        Calculate uniqueness score for a column (0-1 scale).
        
        Args:
            column_data: Pandas Series containing column data
            
        Returns:
            Uniqueness score between 0 and 1
        """
        if len(column_data) == 0:
            return 0.0
        
        unique_count = column_data.nunique()
        total_count = len(column_data)
        
        return unique_count / total_count
    
    def calculate_risk_score(self, pii_type: str, impact: int, uniqueness: float) -> float:
        """
        Calculate risk score based on formula: Risk Score = 20 × Impact × Uniqueness
        
        Args:
            pii_type: Type of PII detected
            impact: Impact score (1-5)
            uniqueness: Uniqueness score (0-1)
            
        Returns:
            Risk score (0-100)
        """
        risk_score = 20 * impact * uniqueness
        return min(risk_score, 100)  # Cap at 100
    
    def categorize_risk(self, risk_score: float) -> str:
        """
        Categorize risk score into Low, Medium, or High.
        
        Args:
            risk_score: Calculated risk score
            
        Returns:
            Risk category string
        """
        if risk_score <= 30:
            return "Low"
        elif risk_score <= 70:
            return "Medium"
        else:
            return "High"
    
    def recommend_action(self, pii_type: str, risk_category: str) -> str:
        """
        Generate anonymization recommendations based on PII type and risk.
        
        Args:
            pii_type: Type of PII detected
            risk_category: Risk category (Low/Medium/High)
            
        Returns:
            Recommended anonymization action
        """
        recommendations = {
            'SSN': 'Tokenization or full masking (e.g., ***-**-1234)',
            'CREDIT_CARD': 'Tokenization or partial masking (e.g., ****-****-****-1234)',
            'NATIONAL_ID': 'Tokenization or hashing with salt',
            'EMAIL': 'Hashing or partial masking (e.g., j***@example.com)',
            'PHONE': 'Masking last 4 digits (e.g., ***-***-1234)',
            'ADDRESS': 'Generalization to city/region level',
            'GPS_COORDINATES': 'Reduce precision to neighborhood level',
            'DATE_OF_BIRTH': 'Generalization to birth year only',
            'DOB': 'Generalization to birth year only',
            'NAME': 'Pseudonymization or tokenization',
            'ID': 'Tokenization or hashing',
            'SALARY': 'Generalization to salary ranges',
            'MEDICAL': 'Remove or encrypt; strict access control required',
            'IBAN': 'Tokenization or partial masking',
            'IP_ADDRESS': 'Remove last octet (e.g., 192.168.1.***)',
            'URL': 'Domain extraction only if needed',
            'AGE': 'Generalization to age ranges (e.g., 20-30)',
            'GENDER': 'Keep if necessary for analysis; consider aggregation',
        }
        
        base_recommendation = recommendations.get(pii_type, 'Apply appropriate anonymization technique')
        
        if risk_category == "High":
            return f"🔴 URGENT: {base_recommendation}"
        elif risk_category == "Medium":
            return f"🟡 {base_recommendation}"
        else:
            return f"🟢 {base_recommendation}"
    
    def analyze_dataset(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Analyze entire dataset for PII and generate comprehensive report.
        
        Args:
            df: Pandas DataFrame to analyze
            
        Returns:
            DataFrame with analysis results
        """
        results = []
        
        for column in df.columns:
            # Pattern-based detection
            pattern_type, pattern_conf = self.detect_pattern_based(df[column])
            
            # Column name heuristic detection
            heuristic_type, heuristic_conf = self.detect_column_name_heuristic(column)
            
            # Combine detections (prioritize higher confidence)
            if pattern_conf > heuristic_conf:
                pii_type = pattern_type
                confidence = pattern_conf
                detection_method = "Pattern-Based"
            elif heuristic_conf > 0:
                pii_type = heuristic_type
                confidence = heuristic_conf
                detection_method = "Column Name Heuristic"
            else:
                pii_type = None
                confidence = 0.0
                detection_method = "None"
            
            # Calculate metrics if PII detected
            if pii_type:
                uniqueness = self.calculate_uniqueness(df[column])
                impact = self.impact_scores.get(pii_type, 2)
                risk_score = self.calculate_risk_score(pii_type, impact, uniqueness)
                risk_category = self.categorize_risk(risk_score)
                recommendation = self.recommend_action(pii_type, risk_category)
                
                results.append({
                    'Column Name': column,
                    'PII Type': pii_type,
                    'Detection Method': detection_method,
                    'Confidence': f"{confidence:.2%}",
                    'Impact': impact,
                    'Uniqueness': f"{uniqueness:.2%}",
                    'Risk Score': f"{risk_score:.2f}",
                    'Risk Category': risk_category,
                    'Recommended Action': recommendation,
                    'Data Type': str(df[column].dtype),
                    'Unique Values': df[column].nunique(),
                    'Null Count': df[column].isna().sum(),
                })
        
        return pd.DataFrame(results)
