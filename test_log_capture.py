#!/usr/bin/env python3
"""
Test script to verify the new log capture system works on Linux servers.
This script tests the streaming log capture functionality.
"""

import asyncio
import json
import time
from pathlib import Path

# Add the app directory to the Python path
import sys
sys.path.append('app')

from scanner.docker_client import DockerClient
from scanner.container_manager import ContainerManager

async def test_log_capture():
    """Test the new log capture functionality."""
    print("Testing new log capture system...")
    
    try:
        # Initialize container manager
        container_manager = ContainerManager()
        
        # Test Docker client
        client = container_manager._get_docker_client()
        if not client.ping():
            print("❌ Docker client ping failed")
            return False
        
        print("✅ Docker client initialized successfully")
        
        # Test streaming logs method
        print("Testing streaming logs method...")
        
        # Create a simple test container that outputs JSON
        test_container_config = {
            'Image': 'alpine:latest',
            'Cmd': ['sh', '-c', 'echo "Starting test"; sleep 2; echo \'{"test": "success", "timestamp": "' + str(time.time()) + '"}\'; echo "Test completed"'],
            'HostConfig': {
                'AutoRemove': True
            }
        }
        
        # Create container
        container_id = client.create_container(test_container_config)
        if not container_id:
            print("❌ Failed to create test container")
            return False
        
        print(f"✅ Test container created: {container_id}")
        
        # Start container
        if not client.start_container(container_id):
            print("❌ Failed to start test container")
            return False
        
        print("✅ Test container started")
        
        # Test streaming logs
        print("Capturing logs with streaming method...")
        logs = await client.stream_container_logs_async(container_id, timeout=10)
        
        if logs:
            print(f"✅ Logs captured successfully ({len(logs)} characters)")
            print("Logs content:")
            print("---")
            print(logs)
            print("---")
            
            # Check if JSON was found
            if '{"test": "success"' in logs:
                print("✅ JSON output found in logs")
                return True
            else:
                print("❌ JSON output not found in logs")
                return False
        else:
            print("❌ No logs captured")
            return False
            
    except Exception as e:
        print(f"❌ Test failed with error: {str(e)}")
        import traceback
        traceback.print_exc()
        return False

async def test_container_manager():
    """Test the container manager's log capture."""
    print("\nTesting Container Manager log capture...")
    
    try:
        container_manager = ContainerManager()
        
        # Test the capture during execution method
        print("Testing capture during execution method...")
        
        # This would require a running container, so we'll just test the method exists
        method = getattr(container_manager, 'capture_container_logs_during_execution', None)
        if method:
            print("✅ capture_container_logs_during_execution method exists")
        else:
            print("❌ capture_container_logs_during_execution method not found")
            return False
        
        print("✅ Container Manager tests passed")
        return True
        
    except Exception as e:
        print(f"❌ Container Manager test failed: {str(e)}")
        return False

async def main():
    """Main test function."""
    print("=" * 60)
    print("Testing New Log Capture System")
    print("=" * 60)
    
    # Test Docker client
    docker_test_passed = await test_log_capture()
    
    # Test Container Manager
    manager_test_passed = await test_container_manager()
    
    print("\n" + "=" * 60)
    print("Test Results Summary")
    print("=" * 60)
    print(f"Docker Client Tests: {'✅ PASSED' if docker_test_passed else '❌ FAILED'}")
    print(f"Container Manager Tests: {'✅ PASSED' if manager_test_passed else '❌ FAILED'}")
    
    if docker_test_passed and manager_test_passed:
        print("\n🎉 All tests passed! The new log capture system should work on Linux servers.")
        return True
    else:
        print("\n💥 Some tests failed. Check the output above for details.")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)
