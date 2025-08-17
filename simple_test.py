#!/usr/bin/env python3
"""
Simple test script to verify basic functionality.
"""

import os
import sys
from pathlib import Path

# Add the current directory to the Python path
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

def test_imports():
    """Test if we can import the basic modules."""
    print("Testing imports...")
    
    try:
        # Test basic imports
        from app.config import settings
        print("✅ Config imported successfully")
        
        from app.scanner.docker_client import DockerClient
        print("✅ DockerClient imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_docker_client():
    """Test Docker client basic functionality."""
    print("\nTesting Docker client...")
    
    try:
        from app.scanner.docker_client import DockerClient
        
        # Create Docker client
        client = DockerClient()
        print("✅ DockerClient created successfully")
        
        # Test ping (this might fail if Docker is not running)
        try:
            if client.ping():
                print("✅ Docker daemon is accessible")
            else:
                print("⚠️  Docker daemon not accessible (this is expected if Docker is not running)")
        except Exception as e:
            print(f"⚠️  Docker ping failed: {e} (this is expected if Docker is not running)")
        
        return True
        
    except Exception as e:
        print(f"❌ Docker client test failed: {e}")
        return False

if __name__ == "__main__":
    print("🚀 Starting simple tests...\n")
    
    # Test imports
    if not test_imports():
        print("\n💥 Import tests FAILED!")
        sys.exit(1)
    
    # Test Docker client
    if not test_docker_client():
        print("\n💥 Docker client tests FAILED!")
        sys.exit(1)
    
    print("\n🎉 All simple tests PASSED!")
    print("\nNext step: Test the full container functionality on your Linux server")
