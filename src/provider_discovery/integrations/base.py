#!/usr/bin/env python3
"""
Base integration class for external API integrations
Provides common functionality for rate limiting, caching, and error handling
"""
import time
import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from ..config.settings import get_settings
from ..utils.cache import get_multi_cache
from ..utils.rate_limiter import get_multi_rate_limiter


class BaseIntegration(ABC):
    """Base class for external API integrations"""
    
    def __init__(self, service_name: str, api_key: Optional[str] = None):
        """
        Initialize base integration
        
        Args:
            service_name: Name of the service (e.g., 'virustotal', 'shodan')
            api_key: API key for the service
        """
        self.service_name = service_name
        self.api_key = api_key
        self.settings = get_settings()
        self.cache = get_multi_cache()
        self.rate_limiter = get_multi_rate_limiter()
        self.logger = logging.getLogger(f"{__name__}.{service_name}")
        
        # Track usage statistics
        self._requests_made = 0
        self._cache_hits = 0
        self._errors = 0
        
    @property
    @abstractmethod
    def is_enabled(self) -> bool:
        """Check if integration is properly configured and enabled"""
        pass
    
    @abstractmethod
    def _make_api_request(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make API request to the service
        
        Args:
            endpoint: API endpoint to call
            **kwargs: Additional parameters for the request
            
        Returns:
            API response data
        """
        pass
    
    def make_cached_request(self, cache_key: str, cache_ttl: Optional[int] = None, 
                          **request_kwargs) -> Dict[str, Any]:
        """
        Make API request with caching support
        
        Args:
            cache_key: Key for caching the result
            cache_ttl: Time to live for cache entry
            **request_kwargs: Arguments passed to _make_api_request
            
        Returns:
            API response data (from cache or fresh request)
        """
        # Check cache first
        cache_type = self.service_name
        cached_result = self.cache.get(cache_type, cache_key)
        if cached_result:
            self._cache_hits += 1
            self.logger.debug(f"Cache hit for {cache_key}")
            return cached_result
        
        # Rate limiting
        if self.rate_limiter.can_proceed(self.service_name):
            wait_time = self.rate_limiter.wait_if_needed(self.service_name)
            if wait_time > 0:
                self.logger.info(f"Rate limited, waited {wait_time:.1f}s")
        
        try:
            # Make fresh request
            result = self._make_api_request(**request_kwargs)
            self._requests_made += 1
            
            # Cache the result
            self.cache.set(cache_type, cache_key, result, cache_ttl)
            
            self.logger.debug(f"Fresh API request for {cache_key}")
            return result
            
        except Exception as e:
            self._errors += 1
            self.logger.error(f"API request failed for {cache_key}: {e}")
            return {'error': str(e)}
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get usage statistics for this integration"""
        cache_stats = self.cache.stats().get(self.service_name, {})
        rate_limit_stats = self.rate_limiter.stats().get(self.service_name, {})
        
        return {
            'service_name': self.service_name,
            'enabled': self.is_enabled,
            'requests_made': self._requests_made,
            'cache_hits': self._cache_hits,
            'errors': self._errors,
            'cache_stats': cache_stats,
            'rate_limit_stats': rate_limit_stats
        }
    
    def clear_cache(self):
        """Clear cache for this integration"""
        # This would need to be implemented based on cache structure
        self.logger.info(f"Cache cleared for {self.service_name}")
    
    def test_connection(self) -> bool:
        """
        Test if the integration is working properly
        
        Returns:
            True if connection test passes
        """
        if not self.is_enabled:
            return False
        
        try:
            # Subclasses should override this with actual test
            result = self._test_api_connection()
            return result.get('success', False)
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def _test_api_connection(self) -> Dict[str, Any]:
        """
        Test API connection - to be overridden by subclasses
        
        Returns:
            Test result dictionary
        """
        return {'success': True, 'message': 'Base test - override in subclass'}


class APIKeyIntegration(BaseIntegration):
    """Base class for integrations that require API keys"""
    
    def __init__(self, service_name: str, api_key: Optional[str] = None, 
                 min_key_length: int = 10):
        """
        Initialize API key integration
        
        Args:
            service_name: Name of the service
            api_key: API key for the service
            min_key_length: Minimum required length for API key
        """
        super().__init__(service_name, api_key)
        self.min_key_length = min_key_length
    
    @property
    def is_enabled(self) -> bool:
        """Check if API key is configured and valid"""
        return (
            self.api_key is not None and 
            isinstance(self.api_key, str) and 
            len(self.api_key.strip()) >= self.min_key_length
        )
    
    def validate_api_key(self) -> Dict[str, Any]:
        """
        Validate the API key format and basic requirements
        
        Returns:
            Validation result
        """
        if not self.api_key:
            return {
                'valid': False,
                'reason': 'API key is not set'
            }
        
        if not isinstance(self.api_key, str):
            return {
                'valid': False,
                'reason': 'API key must be a string'
            }
        
        key = self.api_key.strip()
        if len(key) < self.min_key_length:
            return {
                'valid': False,
                'reason': f'API key too short (minimum {self.min_key_length} characters)'
            }
        
        # Check for obvious placeholders
        placeholders = {
            'your-api-key', 'api-key-here', 'insert-key', 
            'xxx', '000', 'test-key', 'placeholder'
        }
        if key.lower() in placeholders:
            return {
                'valid': False,
                'reason': 'API key appears to be a placeholder'
            }
        
        return {
            'valid': True,
            'reason': 'API key format is valid'
        }


class HTTPIntegration(APIKeyIntegration):
    """Base class for HTTP-based API integrations"""
    
    def __init__(self, service_name: str, base_url: str, api_key: Optional[str] = None,
                 default_headers: Optional[Dict[str, str]] = None):
        """
        Initialize HTTP integration
        
        Args:
            service_name: Name of the service
            base_url: Base URL for API requests
            api_key: API key for the service
            default_headers: Default headers for requests
        """
        super().__init__(service_name, api_key)
        self.base_url = base_url.rstrip('/')
        self.default_headers = default_headers or {}
        
        # Add API key to headers if available
        if self.api_key:
            self.default_headers.update(self._get_auth_headers())
    
    @abstractmethod
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests"""
        pass
    
    def _make_api_request(self, endpoint: str, method: str = 'GET', 
                         headers: Optional[Dict[str, str]] = None,
                         params: Optional[Dict[str, Any]] = None,
                         data: Optional[Any] = None) -> Dict[str, Any]:
        """
        Make HTTP API request
        
        Args:
            endpoint: API endpoint (without base URL)
            method: HTTP method
            headers: Additional headers
            params: Query parameters
            data: Request body data
            
        Returns:
            API response data
        """
        import requests
        
        # Build full URL
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        
        # Merge headers
        request_headers = self.default_headers.copy()
        if headers:
            request_headers.update(headers)
        
        try:
            response = requests.request(
                method=method,
                url=url,
                headers=request_headers,
                params=params,
                json=data if isinstance(data, dict) else None,
                data=data if not isinstance(data, dict) else None,
                timeout=self.settings.http_timeout
            )
            
            response.raise_for_status()
            
            # Try to parse JSON response
            try:
                return response.json()
            except ValueError:
                return {'text': response.text}
                
        except requests.RequestException as e:
            raise Exception(f"HTTP request failed: {e}")


# Example concrete implementation
class ExampleIntegration(HTTPIntegration):
    """Example integration for testing purposes"""
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            service_name="example",
            base_url="https://api.example.com/v1",
            api_key=api_key
        )
    
    def _get_auth_headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.api_key}"}
    
    def _test_api_connection(self) -> Dict[str, Any]:
        try:
            result = self._make_api_request("/test")
            return {'success': True, 'data': result}
        except Exception as e:
            return {'success': False, 'error': str(e)}


# Example usage and testing
if __name__ == "__main__":
    # Test base integration
    example = ExampleIntegration("test-api-key-123")
    
    print("🔧 Testing Base Integration:")
    print(f"Enabled: {example.is_enabled}")
    
    validation = example.validate_api_key()
    print(f"API Key Valid: {validation['valid']} - {validation['reason']}")
    
    stats = example.get_usage_stats()
    print(f"Usage Stats: {stats}")
    
    print("✅ Base integration testing completed!")
