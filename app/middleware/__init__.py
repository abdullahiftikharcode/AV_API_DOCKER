"""
Middleware package for the virus scanner API.

This package contains custom middleware for authentication, logging, and other
request processing functionality.
"""

from .hmac_auth import HMACAuthenticationMiddleware, create_hmac_message, generate_hmac_signature

__all__ = [
    'HMACAuthenticationMiddleware',
    'create_hmac_message', 
    'generate_hmac_signature'
]
