#!/usr/bin/env python3
"""
Rate limiting utilities for Provider Discovery Tool
"""
import time
import threading
from typing import Dict, Optional
from dataclasses import dataclass, field
from collections import deque


@dataclass
class RateLimitConfig:
    """Rate limit configuration"""
    max_calls: int
    time_window: int  # seconds
    burst_allowance: int = 0  # Extra calls allowed in burst


class RateLimiter:
    """Thread-safe rate limiter with sliding window"""
    
    def __init__(self, max_calls: int = 4, time_window: int = 60, burst_allowance: int = 0):
        """
        Initialize rate limiter
        
        Args:
            max_calls: Maximum calls per time window
            time_window: Time window in seconds
            burst_allowance: Extra calls allowed in burst
        """
        self.config = RateLimitConfig(max_calls, time_window, burst_allowance)
        self.calls = deque()
        self.lock = threading.RLock()
        self._blocked_count = 0
        self._total_requests = 0
    
    def wait_if_needed(self, identifier: str = "default") -> float:
        """
        Wait if rate limit would be exceeded
        
        Args:
            identifier: Optional identifier for per-client limiting
            
        Returns:
            Time waited in seconds
        """
        with self.lock:
            now = time.time()
            self._total_requests += 1
            
            # Remove calls outside time window
            while self.calls and now - self.calls[0] >= self.config.time_window:
                self.calls.popleft()
            
            # Check if we need to wait
            max_allowed = self.config.max_calls + self.config.burst_allowance
            if len(self.calls) >= max_allowed:
                # Calculate wait time
                oldest_call = self.calls[0]
                wait_time = self.config.time_window - (now - oldest_call) + 0.1  # Small buffer
                
                if wait_time > 0:
                    self._blocked_count += 1
                    time.sleep(wait_time)
                    now = time.time()
                    
                    # Clean up again after waiting
                    while self.calls and now - self.calls[0] >= self.config.time_window:
                        self.calls.popleft()
                    
                    return wait_time
            
            # Record this call
            self.calls.append(now)
            return 0.0
    
    def can_proceed(self) -> bool:
        """Check if request can proceed without waiting"""
        with self.lock:
            now = time.time()
            
            # Remove calls outside time window
            while self.calls and now - self.calls[0] >= self.config.time_window:
                self.calls.popleft()
            
            max_allowed = self.config.max_calls + self.config.burst_allowance
            return len(self.calls) < max_allowed
    
    def reset(self) -> None:
        """Reset rate limiter"""
        with self.lock:
            self.calls.clear()
            self._blocked_count = 0
            self._total_requests = 0
    
    def stats(self) -> Dict[str, any]:
        """Get rate limiter statistics"""
        with self.lock:
            now = time.time()
            
            # Clean up old calls
            while self.calls and now - self.calls[0] >= self.config.time_window:
                self.calls.popleft()
            
            current_calls = len(self.calls)
            max_calls = self.config.max_calls + self.config.burst_allowance
            
            return {
                'current_calls': current_calls,
                'max_calls': self.config.max_calls,
                'burst_allowance': self.config.burst_allowance,
                'time_window': self.config.time_window,
                'utilization': current_calls / max_calls if max_calls > 0 else 0,
                'blocked_requests': self._blocked_count,
                'total_requests': self._total_requests,
                'block_rate': self._blocked_count / self._total_requests if self._total_requests > 0 else 0
            }
    
    def __repr__(self) -> str:
        """String representation"""
        stats = self.stats()
        return (f"RateLimiter({self.config.max_calls}/{self.config.time_window}s, "
                f"utilization={stats['utilization']:.1%})")


class MultiServiceRateLimiter:
    """Rate limiter for multiple services with different limits"""
    
    def __init__(self):
        """Initialize multi-service rate limiter"""
        self.limiters: Dict[str, RateLimiter] = {}
        self.lock = threading.RLock()
    
    def add_service(self, service_name: str, max_calls: int, time_window: int, 
                   burst_allowance: int = 0) -> None:
        """Add rate limiter for a service"""
        with self.lock:
            self.limiters[service_name] = RateLimiter(
                max_calls=max_calls,
                time_window=time_window,
                burst_allowance=burst_allowance
            )
    
    def wait_if_needed(self, service_name: str, identifier: str = "default") -> float:
        """Wait if rate limit would be exceeded for service"""
        with self.lock:
            if service_name not in self.limiters:
                raise ValueError(f"Unknown service: {service_name}")
            
            return self.limiters[service_name].wait_if_needed(identifier)
    
    def can_proceed(self, service_name: str) -> bool:
        """Check if request can proceed for service"""
        with self.lock:
            if service_name not in self.limiters:
                return True  # No limit configured
            
            return self.limiters[service_name].can_proceed()
    
    def stats(self) -> Dict[str, Dict]:
        """Get statistics for all services"""
        with self.lock:
            return {
                service: limiter.stats()
                for service, limiter in self.limiters.items()
            }
    
    def reset_all(self) -> None:
        """Reset all rate limiters"""
        with self.lock:
            for limiter in self.limiters.values():
                limiter.reset()


# Global rate limiter instances
_global_limiter: Optional[RateLimiter] = None
_global_multi_limiter: Optional[MultiServiceRateLimiter] = None


def get_rate_limiter(max_calls: int = 4, time_window: int = 60) -> RateLimiter:
    """Get global rate limiter instance"""
    global _global_limiter
    if _global_limiter is None:
        _global_limiter = RateLimiter(max_calls, time_window)
    return _global_limiter


def get_multi_rate_limiter() -> MultiServiceRateLimiter:
    """Get global multi-service rate limiter"""
    global _global_multi_limiter
    if _global_multi_limiter is None:
        _global_multi_limiter = MultiServiceRateLimiter()
        
        # Configure common services
        _global_multi_limiter.add_service("virustotal_public", 4, 60)
        _global_multi_limiter.add_service("virustotal_premium", 300, 60)
        _global_multi_limiter.add_service("dns_queries", 100, 60)
        
    return _global_multi_limiter


# Decorator for rate limiting functions
def rate_limited(max_calls: int = 4, time_window: int = 60):
    """Decorator to add rate limiting to functions"""
    def decorator(func):
        limiter = RateLimiter(max_calls, time_window)
        
        def wrapper(*args, **kwargs):
            limiter.wait_if_needed()
            return func(*args, **kwargs)
        
        wrapper.rate_limiter = limiter
        return wrapper
    
    return decorator


# Example usage and testing
if __name__ == "__main__":
    # Test basic rate limiter
    limiter = RateLimiter(max_calls=3, time_window=5)
    
    print("Testing rate limiter...")
    for i in range(6):
        start = time.time()
        wait_time = limiter.wait_if_needed()
        elapsed = time.time() - start
        print(f"Request {i+1}: waited {wait_time:.1f}s, total {elapsed:.1f}s")
        print(f"  Stats: {limiter.stats()}")
    
    # Test multi-service limiter
    print("\nTesting multi-service limiter...")
    multi_limiter = MultiServiceRateLimiter()
    multi_limiter.add_service("api1", 2, 3)
    multi_limiter.add_service("api2", 1, 2)
    
    for service in ["api1", "api2"]:
        print(f"\nTesting {service}:")
        for i in range(3):
            wait_time = multi_limiter.wait_if_needed(service)
            print(f"  Request {i+1}: waited {wait_time:.1f}s")
    
    print(f"\nFinal stats: {multi_limiter.stats()}")
    
    # Test decorator
    @rate_limited(max_calls=2, time_window=3)
    def test_function():
        return "Called!"
    
    print("\nTesting decorated function...")
    for i in range(4):
        start = time.time()
        result = test_function()
        elapsed = time.time() - start
        print(f"Call {i+1}: {result}, took {elapsed:.1f}s")
