"""
Network security module to restrict MalwareBazaar scanner to only allowed domains.
This provides application-level network restrictions instead of iptables.
"""

import socket
import ssl
from typing import Set, Optional
from urllib.parse import urlparse
import aiohttp


class NetworkSecurityManager:
    """Manages network access restrictions for the scanner container"""
    
    def __init__(self):
        # Allowed domains for network access
        self.allowed_domains: Set[str] = {
            'mb-api.abuse.ch',  # MalwareBazaar API
            'api.abuse.ch',     # Abuse.ch API (backup)
            'api.bytescale.com', # Bytescale API
            'upcdn.io',         # Bytescale CDN
        }
        
        # Allowed DNS servers
        self.allowed_dns_servers: Set[str] = {
            '8.8.8.8',      # Google DNS
            '1.1.1.1',      # Cloudflare DNS
            '8.8.4.4',      # Google DNS secondary
            '1.0.0.1',      # Cloudflare DNS secondary
        }
        
    def is_domain_allowed(self, domain: str) -> bool:
        """Check if a domain is in the allowed list"""
        # Remove port if present
        domain_clean = domain.split(':')[0].lower()
        return domain_clean in self.allowed_domains
    
    def is_ip_allowed(self, ip: str) -> bool:
        """Check if an IP is allowed (DNS servers or resolved MalwareBazaar IPs)"""
        return ip in self.allowed_dns_servers
    
    def create_restricted_connector(self) -> aiohttp.TCPConnector:
        """Create a TCP connector with network restrictions"""
        
        class RestrictedTCPConnector(aiohttp.TCPConnector):
            def __init__(self, security_manager, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.security_manager = security_manager
            
            async def _resolve_host(self, host, port, traces=None):
                """Override host resolution to check against allowed domains"""
                # Check if the domain is allowed
                if not self.security_manager.is_domain_allowed(host):
                    raise aiohttp.ClientConnectorError(
                        connection_key=aiohttp.client.ConnectionKey(host, port, is_ssl=False),
                        os_error=OSError(f"Domain '{host}' not in allowed list for security reasons")
                    )
                
                # Proceed with normal resolution if domain is allowed
                return await super()._resolve_host(host, port, traces)
        
        return RestrictedTCPConnector(
            self,
            limit=10,
            limit_per_host=5,
            ttl_dns_cache=300,
            use_dns_cache=True
        )


# Global instance
network_security = NetworkSecurityManager()


def get_secure_session() -> aiohttp.ClientSession:
    """Get an aiohttp session with network security restrictions"""
    connector = network_security.create_restricted_connector()
    timeout = aiohttp.ClientTimeout(total=10)
    
    return aiohttp.ClientSession(
        connector=connector,
        timeout=timeout,
        headers={
            'User-Agent': 'MalwareAnalysisSystem/1.0',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    )
