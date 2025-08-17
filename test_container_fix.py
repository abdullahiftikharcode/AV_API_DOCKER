#!/usr/bin/env python3
"""
Test script to verify the container fix is working.
This script tests the new container configuration and cleanup.
"""

import asyncio
import json
import time
import os
import sys
from pathlib import Path

# Add the current directory to the Python path so we can import from app
current_dir = Path(__file__).parent
sys.path.insert(0, str(current_dir))

try:
    from app.scanner.container_manager import ContainerManager
except ImportError as e:
    print(f"❌ Import error: {e}")
    print("Make sure you're running this from the project root directory")
    sys.exit(1)

async def test_container_fix():
    """Test the container fix functionality."""
    print("Testing container fix...")
    
    try:
        # Initialize container manager
        container_manager = ContainerManager()
        
        # Test Docker client
        client = container_manager._get_docker_client()
        if not client.ping():
            print("❌ Docker daemon not accessible")
            return False
        
        print("✅ Docker daemon accessible")
        
        # Test container creation with new config
        test_file = Path("test_hmac_client.py")
        if not test_file.exists():
            print("❌ Test file not found")
            return False
        
        print("✅ Test file found")
        
        # Start a scan
        print("🚀 Starting test scan...")
        result = await container_manager.scan_file_in_container(test_file)
        
        if result.success:
            print("✅ Scan completed successfully!")
            print(f"📊 Result: {json.dumps(result.result, indent=2)}")
            return True
        else:
            print(f"❌ Scan failed: {result.error}")
            return False
            
    except Exception as e:
        print(f"❌ Test failed with error: {str(e)}")
        return False

if __name__ == "__main__":
    success = asyncio.run(test_container_fix())
    if success:
        print("\n🎉 Container fix test PASSED!")
    else:
        print("\n💥 Container fix test FAILED!")
        sys.exit(1)
