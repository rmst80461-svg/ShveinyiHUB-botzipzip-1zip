import hashlib
import time
from typing import Dict, Optional

class ResponseCache:
    def __init__(self, ttl: int = 3600):  # Cache for 1 hour
        self.cache: Dict[str, tuple] = {}
        self.ttl = ttl
    
    def _hash_key(self, text: str) -> str:
        """Create hash of text for cache key"""
        return hashlib.md5(text.lower().encode()).hexdigest()
    
    def get(self, text: str) -> Optional[str]:
        """Get cached response"""
        key = self._hash_key(text)
        
        if key in self.cache:
            response, timestamp = self.cache[key]
            # Check if cache expired
            if time.time() - timestamp < self.ttl:
                return response
            else:
                del self.cache[key]
        
        return None
    
    def set(self, text: str, response: str) -> None:
        """Cache response"""
        key = self._hash_key(text)
        self.cache[key] = (response, time.time())
    
    def clear_old(self) -> None:
        """Remove expired entries"""
        now = time.time()
        expired = [k for k, (_, t) in self.cache.items() if now - t > self.ttl]
        for k in expired:
            del self.cache[k]

cache = ResponseCache()
