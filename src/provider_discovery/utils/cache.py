#!/usr/bin/env python3
"""
Caching utilities for Provider Discovery Tool
"""
import time
import threading
from typing import Any, Dict, Optional, Tuple
from dataclasses import dataclass, field


@dataclass
class CacheEntry:
    """Single cache entry with timestamp"""
    data: Any
    timestamp: float
    ttl: float
    
    def is_expired(self) -> bool:
        """Check if entry is expired"""
        return time.time() - self.timestamp > self.ttl


class Cache:
    """Thread-safe in-memory cache with TTL support"""
    
    def __init__(self, default_ttl: int = 3600, max_size: int = 1000):
        """
        Initialize cache
        
        Args:
            default_ttl: Default time to live in seconds
            max_size: Maximum number of entries
        """
        self.default_ttl = default_ttl
        self.max_size = max_size
        self._cache: Dict[str, CacheEntry] = {}
        self._lock = threading.RLock()
        self._hits = 0
        self._misses = 0
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache if not expired"""
        with self._lock:
            if key not in self._cache:
                self._misses += 1
                return None
            
            entry = self._cache[key]
            if entry.is_expired():
                del self._cache[key]
                self._misses += 1
                return None
            
            self._hits += 1
            return entry.data
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in cache with optional TTL"""
        with self._lock:
            # Use provided TTL or default
            cache_ttl = ttl if ttl is not None else self.default_ttl
            
            # Check if we need to evict entries
            if len(self._cache) >= self.max_size and key not in self._cache:
                self._evict_oldest()
            
            # Store the entry
            self._cache[key] = CacheEntry(
                data=value,
                timestamp=time.time(),
                ttl=cache_ttl
            )
    
    def delete(self, key: str) -> bool:
        """Delete entry from cache"""
        with self._lock:
            if key in self._cache:
                del self._cache[key]
                return True
            return False
    
    def clear(self) -> None:
        """Clear all cache entries"""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0
    
    def clear_expired(self) -> int:
        """Remove all expired entries and return count"""
        with self._lock:
            expired_keys = [
                key for key, entry in self._cache.items()
                if entry.is_expired()
            ]
            
            for key in expired_keys:
                del self._cache[key]
            
            return len(expired_keys)
    
    def _evict_oldest(self) -> None:
        """Evict oldest entry to make room"""
        if not self._cache:
            return
        
        oldest_key = min(
            self._cache.keys(),
            key=lambda k: self._cache[k].timestamp
        )
        del self._cache[oldest_key]
    
    def size(self) -> int:
        """Get current cache size"""
        with self._lock:
            return len(self._cache)
    
    def hit_rate(self) -> float:
        """Get cache hit rate"""
        with self._lock:
            total = self._hits + self._misses
            return self._hits / total if total > 0 else 0.0
    
    def stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        with self._lock:
            total_requests = self._hits + self._misses
            return {
                'size': len(self._cache),
                'max_size': self.max_size,
                'hits': self._hits,
                'misses': self._misses,
                'total_requests': total_requests,
                'hit_rate': self.hit_rate(),
                'default_ttl': self.default_ttl
            }
    
    def __contains__(self, key: str) -> bool:
        """Check if key exists and is not expired"""
        return self.get(key) is not None
    
    def __len__(self) -> int:
        """Get cache size"""
        return self.size()
    
    def __repr__(self) -> str:
        """String representation"""
        stats = self.stats()
        return (f"Cache(size={stats['size']}, "
                f"hit_rate={stats['hit_rate']:.2%}, "
                f"ttl={stats['default_ttl']}s)")


class MultiLevelCache:
    """Multi-level cache with different TTLs for different data types"""
    
    def __init__(self, default_ttl: int = 3600):
        """Initialize multi-level cache"""
        self.caches = {
            'ip': Cache(default_ttl=default_ttl * 2, max_size=2000),     # IP addresses cache longer
            'dns': Cache(default_ttl=default_ttl, max_size=1000),        # DNS records
            'whois': Cache(default_ttl=default_ttl * 4, max_size=500),   # WHOIS data cache longest
            'headers': Cache(default_ttl=default_ttl // 2, max_size=500), # Headers cache shortest
            'virustotal': Cache(default_ttl=default_ttl, max_size=1000),  # VirusTotal data
            'bgp_analysis': Cache(default_ttl=default_ttl * 2, max_size=2000), # BGP data (2h TTL)
            'ssl_analysis': Cache(default_ttl=default_ttl * 4, max_size=1000), # SSL data (4h TTL)
            'enhanced_dns': Cache(default_ttl=default_ttl // 2, max_size=2000), # Enhanced DNS (30min TTL)
            'geo_intelligence': Cache(default_ttl=default_ttl * 6, max_size=1500), # Geographic data (6h TTL)
            'threat_intelligence': Cache(default_ttl=default_ttl * 4, max_size=1000), # Threat data (4h TTL)
            'hurricane_electric': Cache(default_ttl=default_ttl * 8, max_size=800) # HE BGP data (8h TTL)
        }
    
    def get(self, cache_type: str, key: str) -> Optional[Any]:
        """Get value from specific cache"""
        if cache_type not in self.caches:
            raise ValueError(f"Unknown cache type: {cache_type}")
        return self.caches[cache_type].get(key)
    
    def set(self, cache_type: str, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Set value in specific cache"""
        if cache_type not in self.caches:
            raise ValueError(f"Unknown cache type: {cache_type}")
        self.caches[cache_type].set(key, value, ttl)
    
    def clear_expired(self) -> Dict[str, int]:
        """Clear expired entries from all caches"""
        return {
            cache_type: cache.clear_expired()
            for cache_type, cache in self.caches.items()
        }
    
    def stats(self) -> Dict[str, Dict[str, Any]]:
        """Get statistics for all caches"""
        return {
            cache_type: cache.stats()
            for cache_type, cache in self.caches.items()
        }
    
    def clear_all(self) -> None:
        """Clear all caches"""
        for cache in self.caches.values():
            cache.clear()


# Global cache instances
_global_cache: Optional[Cache] = None
_global_multi_cache: Optional[MultiLevelCache] = None


def get_cache(max_size: int = 1000, ttl: int = 3600) -> Cache:
    """Get global cache instance"""
    global _global_cache
    if _global_cache is None:
        _global_cache = Cache(default_ttl=ttl, max_size=max_size)
    return _global_cache


def get_multi_cache(ttl: int = 3600) -> MultiLevelCache:
    """Get global multi-level cache instance"""
    global _global_multi_cache
    if _global_multi_cache is None:
        _global_multi_cache = MultiLevelCache(default_ttl=ttl)
    return _global_multi_cache


# Example usage and testing
if __name__ == "__main__":
    # Test basic cache
    cache = Cache(default_ttl=5, max_size=3)
    
    # Test basic operations
    cache.set("key1", "value1")
    cache.set("key2", "value2", ttl=2)
    cache.set("key3", "value3")
    
    print(f"Cache stats: {cache.stats()}")
    print(f"key1: {cache.get('key1')}")
    print(f"key2: {cache.get('key2')}")
    
    # Test eviction
    cache.set("key4", "value4")  # Should evict oldest
    print(f"After eviction: size={cache.size()}")
    
    # Test expiration
    time.sleep(3)
    print(f"key2 after expiration: {cache.get('key2')}")  # Should be None
    
    # Test multi-level cache
    multi_cache = MultiLevelCache()
    multi_cache.set('ip', '1.2.3.4', 'AWS')
    multi_cache.set('dns', 'example.com', ['ns1.example.com'])
    
    print(f"Multi-cache stats: {multi_cache.stats()}")
