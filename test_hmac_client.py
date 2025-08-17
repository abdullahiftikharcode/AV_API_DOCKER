#!/usr/bin/env python3
"""
Test client for HMAC-authenticated virus scanner API.

This script demonstrates how to send properly signed requests to the API
with HMAC-SHA256 authentication.
"""

import hmac
import hashlib
import time
import requests
import json
import argparse
import sys
from pathlib import Path
from typing import Optional


class HMACClient:
    """Client for sending HMAC-authenticated requests to the virus scanner API."""
    
    def __init__(self, base_url: str, secret_key: str, timeout: int = 300):
        """
        Initialize the HMAC client.
        
        Args:
            base_url: Base URL of the API (e.g., "http://localhost:8080")
            secret_key: Secret key for HMAC signing
            timeout: Request timeout in seconds (default: 300 seconds = 5 minutes)
        """
        self.base_url = base_url.rstrip('/')
        self.secret_key = secret_key
        self.timeout = timeout
        
    def _create_signature(self, timestamp: str, method: str, path: str, body: str) -> str:
        """
        Create HMAC-SHA256 signature for a request.
        
        Args:
            timestamp: Unix timestamp as string
            method: HTTP method (GET, POST, etc.)
            path: Request path (e.g., "/api/scan")
            body: Request body as string
            
        Returns:
            str: HMAC signature in hexadecimal format
        """
        # Create message: timestamp + method + path + body
        message = timestamp + method + path + body
        
        # Generate HMAC-SHA256 signature
        signature = hmac.new(
            self.secret_key.encode(),
            message.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _prepare_request_headers(self, method: str, path: str, body: str) -> dict:
        """
        Prepare headers with HMAC signature and timestamp.
        
        Args:
            method: HTTP method
            path: Request path
            body: Request body as string
            
        Returns:
            dict: Headers dictionary with X-Signature and X-Timestamp
        """
        # Generate timestamp
        timestamp = str(int(time.time()))
        
        # Create signature
        signature = self._create_signature(timestamp, method, path, body)
        
        # Prepare headers
        headers = {
            'X-Signature': signature,
            'X-Timestamp': timestamp,
        }
        
        return headers
    
    def scan_file(self, file_path: str) -> dict:
        """
        Send a file to be scanned by the virus scanner API.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            dict: API response
            
        Raises:
            FileNotFoundError: If the file doesn't exist
            requests.RequestException: If the request fails
        """
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Prepare the multipart form data
        with open(file_path, 'rb') as f:
            files = {'file': (file_path.name, f, 'application/octet-stream')}
            
            # For multipart requests, we need to handle the body differently
            # Since we can't predict the exact multipart boundary, we'll use an empty body
            # for signature calculation and let requests handle the multipart encoding
            method = "POST"
            path = "/api/scan"
            body = ""  # Empty body for multipart requests
            
            # Prepare headers
            headers = self._prepare_request_headers(method, path, body)
            
            # Make the request
            url = f"{self.base_url}{path}"
            
            print(f"Sending signed request to: {url}")
            print(f"File: {file_path.name} ({file_path.stat().st_size} bytes)")
            print(f"Timestamp: {headers['X-Timestamp']}")
            print(f"Signature: {headers['X-Signature']}")
            print(f"Timeout: {self.timeout} seconds")
            print("Waiting for response...")
            
            try:
                response = requests.post(
                    url, 
                    files=files, 
                    headers=headers, 
                    timeout=self.timeout,
                    stream=True  # Stream response to avoid memory issues
                )
                
                print(f"Response received! Status: {response.status_code}")
                
                # Read response content
                if response.headers.get('content-type', '').startswith('application/json'):
                    try:
                        data = response.json()
                    except json.JSONDecodeError:
                        data = response.text
                else:
                    data = response.text
                
                return {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'data': data
                }
                
            except requests.exceptions.Timeout:
                print(f"Request timed out after {self.timeout} seconds")
                raise requests.exceptions.Timeout(f"Request timed out after {self.timeout} seconds")
            except requests.exceptions.RequestException as e:
                print(f"Request failed: {e}")
                raise
    
    def health_check(self) -> dict:
        """
        Perform a health check (usually doesn't require HMAC).
        
        Returns:
            dict: API response
        """
        url = f"{self.base_url}/health"
        print(f"Performing health check to: {url}")
        
        try:
            response = requests.get(url, timeout=30)  # 30 second timeout for health check
            print(f"Health check response received! Status: {response.status_code}")
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'data': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
            }
        except requests.exceptions.Timeout:
            print("Health check timed out after 30 seconds")
            raise requests.exceptions.Timeout("Health check timed out after 30 seconds")
        except requests.exceptions.RequestException as e:
            print(f"Health check failed: {e}")
            raise
    
    def send_json_request(self, method: str, path: str, data: dict = None) -> dict:
        """
        Send a JSON request with HMAC authentication.
        
        Args:
            method: HTTP method
            path: Request path
            data: JSON data to send
            
        Returns:
            dict: API response
        """
        # Prepare body
        body = json.dumps(data) if data else ""
        
        # Prepare headers
        headers = self._prepare_request_headers(method, path, body)
        headers['Content-Type'] = 'application/json'
        
        # Make request
        url = f"{self.base_url}{path}"
        
        print(f"Sending {method} request to: {url}")
        print(f"Body: {body}")
        print(f"Timestamp: {headers['X-Timestamp']}")
        print(f"Signature: {headers['X-Signature']}")
        print(f"Timeout: {self.timeout} seconds")
        print("Waiting for response...")
        
        try:
            response = requests.request(
                method, 
                url, 
                data=body, 
                headers=headers, 
                timeout=self.timeout
            )
            
            print(f"Response received! Status: {response.status_code}")
            
            return {
                'status_code': response.status_code,
                'headers': dict(response.headers),
                'data': response.json() if response.headers.get('content-type', '').startswith('application/json') else response.text
            }
        except requests.exceptions.Timeout:
            print(f"Request timed out after {self.timeout} seconds")
            raise requests.exceptions.Timeout(f"Request timed out after {self.timeout} seconds")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            raise


def main():
    """Main function to run the test client."""
    parser = argparse.ArgumentParser(description="Test HMAC-authenticated virus scanner API")
    parser.add_argument("--url", default="http://localhost:8080", help="API base URL")
    parser.add_argument("--secret", default="8e0a9393b877bc3bf1a1debe018716f0c5830615da9a13bef482515d52f1a2f2", help="HMAC secret key")
    parser.add_argument("--file", help="File to scan")
    parser.add_argument("--health", action="store_true", help="Perform health check")
    parser.add_argument("--test-json", action="store_true", help="Test JSON endpoint")
    parser.add_argument("--timeout", type=int, default=300, help="Request timeout in seconds (default: 300)")
    
    args = parser.parse_args()
    
    # Initialize client
    client = HMACClient(args.url, args.secret, args.timeout)
    
    try:
        if args.health:
            print("=== Health Check ===")
            result = client.health_check()
            print(f"Status: {result['status_code']}")
            print(f"Response: {json.dumps(result['data'], indent=2)}")
            
        elif args.file:
            print("=== File Scan ===")
            result = client.scan_file(args.file)
            print(f"Status: {result['status_code']}")
            print(f"Response: {json.dumps(result['data'], indent=2)}")
            
        elif args.test_json:
            print("=== JSON Request Test ===")
            test_data = {"test": "data", "timestamp": int(time.time())}
            result = client.send_json_request("POST", "/api/test", test_data)
            print(f"Status: {result['status_code']}")
            print(f"Response: {json.dumps(result['data'], indent=2)}")
            
        else:
            print("Please specify an action: --file, --health, or --test-json")
            print("Use --help for more information")
            
    except requests.exceptions.Timeout as e:
        print(f"Timeout Error: {e}")
        print("The server took too long to respond. This could indicate:")
        print("- The server is overloaded")
        print("- The file scan is taking longer than expected")
        print("- There's a network issue")
        print(f"Try increasing the timeout with --timeout <seconds> (current: {args.timeout}s)")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
