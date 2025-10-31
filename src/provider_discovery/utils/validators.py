#!/usr/bin/env python3
"""
Validation utilities for Provider Discovery Tool
"""
import re
import ipaddress
from typing import Tuple, Optional, List, Dict, Any
from urllib.parse import urlparse
import pandas as pd


class URLValidator:
    """URL validation and normalization utilities"""
    
    # Domain validation pattern
    DOMAIN_PATTERN = re.compile(
        r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$'
    )
    
    # Common invalid values
    INVALID_VALUES = {'nan', 'n/a', 'null', 'none', '', 'undefined', 'null'}
    
    @classmethod
    def validate_url(cls, url: str) -> Tuple[bool, str]:
        """
        Validate and clean URL format
        
        Args:
            url: URL to validate
            
        Returns:
            Tuple of (is_valid, cleaned_url_or_error_message)
        """
        if not url or not isinstance(url, str):
            return False, "URL cannot be empty"
        
        # Clean whitespace and common issues
        url = str(url).strip()
        if not url or url.lower() in cls.INVALID_VALUES:
            return False, "URL cannot be empty"
        
        # Remove common prefixes that users might add
        url = url.replace('www.', '').replace('WWW.', '')
        
        # Add protocol if missing for parsing
        parse_url = url
        if not url.startswith(('http://', 'https://')):
            parse_url = 'https://' + url
        
        try:
            parsed = urlparse(parse_url)
            if not parsed.netloc:
                return False, "Invalid URL format"
            
            # Extract clean domain
            domain = parsed.netloc.lower()
            
            # Validate domain format
            if not cls.DOMAIN_PATTERN.match(domain):
                return False, f"Invalid domain format: {domain}"
            
            # Return clean URL without protocol for processing
            clean_url = domain + (parsed.path if parsed.path != '/' else '')
            return True, clean_url
            
        except Exception as e:
            return False, f"Invalid URL format: {str(e)}"
    
    @classmethod
    def fix_common_url_issues(cls, url: str) -> str:
        """
        Attempt to fix common URL issues
        
        Args:
            url: URL to fix
            
        Returns:
            Fixed URL
        """
        url = url.strip()
        
        # Try adding .com if it looks like a company name
        if '.' not in url and len(url) > 2 and url.isalnum():
            return url + '.com'
        
        # Remove protocols and www
        url = re.sub(r'^https?://', '', url)
        url = re.sub(r'^www\.', '', url)
        
        # Remove trailing slashes and paths for basic domain
        url = url.split('/')[0]
        
        return url
    
    @classmethod
    def extract_domain(cls, url: str) -> Optional[str]:
        """
        Extract domain from URL
        
        Args:
            url: URL to extract domain from
            
        Returns:
            Domain or None if invalid
        """
        is_valid, result = cls.validate_url(url)
        if is_valid:
            return result.split('/')[0]  # Remove path
        return None


class IPValidator:
    """IP address validation utilities"""
    
    @classmethod
    def is_valid_ip(cls, ip: str) -> bool:
        """Check if string is valid IP address"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    @classmethod
    def is_ipv4(cls, ip: str) -> bool:
        """Check if string is valid IPv4 address"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ValueError:
            return False
    
    @classmethod
    def is_ipv6(cls, ip: str) -> bool:
        """Check if string is valid IPv6 address"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False
    
    @classmethod
    def is_private_ip(cls, ip: str) -> bool:
        """Check if IP address is private"""
        try:
            addr = ipaddress.ip_address(ip)
            return addr.is_private
        except ValueError:
            return False
    
    @classmethod
    def normalize_ip(cls, ip: str) -> Optional[str]:
        """Normalize IP address format"""
        try:
            addr = ipaddress.ip_address(ip)
            return str(addr)
        except ValueError:
            return None


class CSVValidator:
    """CSV file validation utilities"""
    
    REQUIRED_COLUMNS = ['Company', 'URL']
    MAX_ROWS = 10000  # Safety limit
    
    @classmethod
    def validate_csv_structure(cls, df: pd.DataFrame) -> Tuple[List[str], List[str], Optional[pd.DataFrame]]:
        """
        Validate and clean CSV file structure and content
        
        Args:
            df: DataFrame to validate
            
        Returns:
            Tuple of (errors, warnings, cleaned_dataframe)
        """
        errors = []
        warnings = []
        
        # Check required columns
        missing_columns = [col for col in cls.REQUIRED_COLUMNS if col not in df.columns]
        if missing_columns:
            errors.append(f"Missing required columns: {', '.join(missing_columns)}")
            return errors, warnings, None
        
        # Check for empty DataFrame
        if df.empty:
            errors.append("CSV file is empty")
            return errors, warnings, None
        
        # Check size limits
        if len(df) > cls.MAX_ROWS:
            errors.append(f"CSV file too large: {len(df)} rows (max {cls.MAX_ROWS})")
            return errors, warnings, None
        
        # Clean and validate data
        df_clean = df.copy()
        
        # Clean whitespace and normalize data
        for col in df_clean.columns:
            if df_clean[col].dtype == 'object':
                df_clean[col] = df_clean[col].astype(str).str.strip()
        
        # Process each row and try to fix issues
        valid_rows = []
        cleaned_count = 0
        
        for idx, row in df_clean.iterrows():
            # Clean Company name
            company = str(row.get('Company', '')).strip()
            if not company or company.lower() in URLValidator.INVALID_VALUES:
                # Try to generate company name from URL if possible
                url_val = str(row.get('URL', '')).strip()
                if url_val and url_val.lower() not in URLValidator.INVALID_VALUES:
                    domain = URLValidator.extract_domain(url_val)
                    if domain:
                        company = domain.split('.')[0].title()
                        df_clean.at[idx, 'Company'] = company
                        warnings.append(f"Row {idx + 2}: Generated company name '{company}' from URL")
                        cleaned_count += 1
                    else:
                        continue  # Skip row - no valid company or URL
                else:
                    continue  # Skip row - no company or URL
            
            # Clean and validate URL
            url = str(row.get('URL', '')).strip()
            if not url or url.lower() in URLValidator.INVALID_VALUES:
                continue  # Skip row - no URL
            
            is_valid, url_or_error = URLValidator.validate_url(url)
            if not is_valid:
                # Try common fixes
                fixed_url = URLValidator.fix_common_url_issues(url)
                is_valid, url_or_error = URLValidator.validate_url(fixed_url)
                if is_valid:
                    warnings.append(f"Row {idx + 2}: Fixed URL '{url}' → '{url_or_error}'")
                    cleaned_count += 1
                else:
                    warnings.append(f"Row {idx + 2}: Skipped invalid URL '{url}' - {url_or_error}")
                    continue
            
            # Update with cleaned URL
            df_clean.at[idx, 'URL'] = url_or_error
            df_clean.at[idx, 'Company'] = company
            valid_rows.append(idx)
        
        # Filter only valid rows
        if valid_rows:
            df_clean = df_clean.iloc[valid_rows].reset_index(drop=True)
        else:
            df_clean = pd.DataFrame(columns=cls.REQUIRED_COLUMNS)
        
        # Add informative warnings
        skipped_count = len(df) - len(df_clean)
        if skipped_count > 0:
            warnings.append(f"Automatically cleaned {cleaned_count} rows and excluded {skipped_count} invalid rows")
        
        if len(df_clean) > 50:
            warnings.append("Large file detected. Processing may take several minutes.")
        
        if len(df_clean) == 0:
            errors.append("No valid data rows found after cleaning")
        
        return errors, warnings, df_clean


class DataValidator:
    """General data validation utilities"""
    
    @classmethod
    def validate_provider_name(cls, name: str) -> bool:
        """Validate provider name format"""
        if not name or not isinstance(name, str):
            return False
        
        name = name.strip()
        if len(name) < 2 or len(name) > 50:
            return False
        
        # Should contain only letters, numbers, spaces, hyphens, dots
        return re.match(r'^[a-zA-Z0-9\s\-\.]+$', name) is not None
    
    @classmethod
    def validate_confidence_score(cls, score: Any) -> bool:
        """Validate confidence score (0-100)"""
        try:
            score_num = float(score)
            return 0 <= score_num <= 100
        except (ValueError, TypeError):
            return False
    
    @classmethod
    def sanitize_string(cls, text: str, max_length: int = 255) -> str:
        """Sanitize string input"""
        if not isinstance(text, str):
            text = str(text)
        
        # Remove control characters
        text = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', text)
        
        # Limit length
        if len(text) > max_length:
            text = text[:max_length-3] + '...'
        
        return text.strip()
    
    @classmethod
    def validate_api_key(cls, api_key: str, min_length: int = 10) -> bool:
        """Basic API key validation"""
        if not api_key or not isinstance(api_key, str):
            return False
        
        api_key = api_key.strip()
        
        # Basic length check
        if len(api_key) < min_length:
            return False
        
        # Should not contain obvious placeholders
        placeholders = {'your-api-key', 'api-key-here', 'insert-key', 'xxx', '000'}
        if api_key.lower() in placeholders:
            return False
        
        return True


# Convenience functions for backward compatibility
def validate_url(url: str) -> Tuple[bool, str]:
    """Convenience function for URL validation"""
    return URLValidator.validate_url(url)


def is_valid_ip(ip: str) -> bool:
    """Convenience function for IP validation"""
    return IPValidator.is_valid_ip(ip)


def validate_provider_name(name: str) -> bool:
    """Convenience function for provider name validation"""
    return DataValidator.validate_provider_name(name)


def validate_api_key(api_key: str, min_length: int = 10) -> bool:
    """Convenience function for API key validation"""
    return DataValidator.validate_api_key(api_key, min_length)


# Example usage and testing
if __name__ == "__main__":
    # Test URL validation
    test_urls = [
        "google.com",
        "https://github.com",
        "www.cloudflare.com",
        "invalid..domain",
        "just-text",
        "",
        "microsoft",  # Should be fixed to microsoft.com
    ]
    
    print("🌐 URL Validation Tests:")
    for url in test_urls:
        is_valid, result = URLValidator.validate_url(url)
        status = "✅" if is_valid else "❌"
        print(f"{status} '{url}' → {result}")
    
    # Test IP validation
    test_ips = [
        "192.168.1.1",
        "8.8.8.8",
        "2001:db8::1",
        "invalid-ip",
        "256.256.256.256"
    ]
    
    print("\n🌍 IP Validation Tests:")
    for ip in test_ips:
        valid = IPValidator.is_valid_ip(ip)
        ipv4 = IPValidator.is_ipv4(ip)
        private = IPValidator.is_private_ip(ip) if valid else False
        status = "✅" if valid else "❌"
        details = f"IPv4: {ipv4}, Private: {private}" if valid else "Invalid"
        print(f"{status} '{ip}' → {details}")
    
    # Test data validation
    print("\n📊 Data Validation Tests:")
    test_providers = ["Cloudflare", "AWS", "G-Core", "", "Very-Long-Provider-Name-That-Exceeds-Limits"]
    for provider in test_providers:
        valid = DataValidator.validate_provider_name(provider)
        status = "✅" if valid else "❌"
        print(f"{status} Provider: '{provider}'")
    
    test_scores = [95, 0, 100, -5, 150, "invalid", 75.5]
    for score in test_scores:
        valid = DataValidator.validate_confidence_score(score)
        status = "✅" if valid else "❌"
        print(f"{status} Score: {score}")
    
    print("\n✅ Validation tests completed!")
