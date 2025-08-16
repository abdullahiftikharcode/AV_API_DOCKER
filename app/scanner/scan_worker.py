#!/usr/bin/env python3
"""
Scan worker that runs inside a container to perform virus scanning.
This is isolated from the main API to ensure security.
"""

import argparse
import json
import sys
import time
import os
from pathlib import Path
from datetime import datetime

# Add the app directory to Python path
sys.path.insert(0, '/app')

print("DEBUG: Python path:", sys.path)
print("DEBUG: Current working directory:", os.getcwd())
print("DEBUG: Files in /app:", os.listdir('/app') if os.path.exists('/app') else "No /app directory")

try:
    from app.scanner.ensemble import EnsembleScanner
    print("DEBUG: Successfully imported EnsembleScanner")
except ImportError as e:
    print(f"ERROR: Failed to import EnsembleScanner: {e}")
    print("DEBUG: Available modules in app.scanner:", os.listdir('/app/app/scanner') if os.path.exists('/app/app/scanner') else "No scanner directory")
    sys.exit(1)

try:
    from app.utils.file_handler import FileHandler
    print("DEBUG: Successfully imported FileHandler")
except ImportError as e:
    print(f"ERROR: Failed to import FileHandler: {e}")
    sys.exit(1)

try:
    from app.config import settings
    print("DEBUG: Successfully imported settings")
except ImportError as e:
    print(f"ERROR: Failed to import settings: {e}")
    sys.exit(1)


async def main():
    """Main scan worker function."""
    # Initialize variables at the top level
    file_path = None
    container_start_time = time.time()  # Track total container time
    
    try:
        parser = argparse.ArgumentParser(description='Virus Scanner Worker')
        parser.add_argument('--file', help='File to scan')
        parser.add_argument('--timeout', type=int, default=300, help='Scan timeout in seconds')
        
        args = parser.parse_args()
        
        # If no file argument provided, try environment variables
        timeout = args.timeout
        
        # Initialize scan_mode with default value
        scan_mode = 'file'
        
        if args.file:
            file_path = Path(args.file)
        else:
            # Try environment variables
            scan_file_path = os.environ.get('SCAN_FILE_PATH')
            scan_mode = os.environ.get('SCAN_MODE', 'file')
            
            if scan_file_path:
                file_path = Path(scan_file_path)
                print(f"DEBUG: Using environment variable SCAN_FILE_PATH: {scan_file_path}")
                print(f"DEBUG: Scan mode: {scan_mode}")
            
            # Try config file
            if not file_path and os.path.exists('/scan_config.env'):
                print("DEBUG: Loading configuration from /scan_config.env")
                with open('/scan_config.env', 'r') as f:
                    for line in f:
                        if line.strip() and not line.startswith('#'):
                            key, value = line.strip().split('=', 1)
                            if key == 'SCAN_FILE_PATH':
                                file_path = Path(value)
                                print(f"DEBUG: Using config file SCAN_FILE_PATH: {value}")
                                break
                            elif key == 'SCAN_MODE':
                                scan_mode = value
                                print(f"DEBUG: Scan mode from config: {value}")
        
        # If still no file path, try to find files in /scan directory
        if not file_path:
            scan_dir = Path('/scan')
            if scan_dir.exists() and any(scan_dir.iterdir()):
                scan_files = list(scan_dir.iterdir())
                if scan_files:
                    file_path = scan_files[0]
                    print(f"DEBUG: Found file in /scan directory: {file_path}")
        
        # Handle streaming mode - wait for file to be available
        if scan_mode == 'streaming' and not file_path:
            print("DEBUG: Streaming mode detected, waiting for file to be available...")
            max_wait_time = 30  # Wait up to 30 seconds for file
            wait_start = time.time()
            
            while not file_path and (time.time() - wait_start) < max_wait_time:
                scan_dir = Path('/scan')
                if scan_dir.exists() and any(scan_dir.iterdir()):
                    scan_files = list(scan_dir.iterdir())
                    if scan_files:
                        file_path = scan_files[0]
                        print(f"DEBUG: File appeared in /scan directory: {file_path}")
                        break
                time.sleep(1)  # Wait 1 second before checking again
            
            if not file_path:
                print("WARNING: No file found after waiting in streaming mode")
        
        if not file_path:
            container_duration_ms = int((time.time() - container_start_time) * 1000)
            print(json.dumps({
                'safe': True,
                'threats': [],
                'scanTime': datetime.utcnow().isoformat(),
                'scanDurationMs': 0,  # No actual scanning
                'containerDurationMs': container_duration_ms,  # Total container time
                'fileSize': 0,
                'fileName': 'unknown',
                'scanEngine': 'container_ensemble',
                'error': 'No file specified and no files found in /scan directory'
            }))
            return
        
        # Debug: List contents of /scan directory
        scan_dir = Path('/scan')
        if scan_dir.exists():
            print(f"DEBUG: /scan directory exists, contents: {list(scan_dir.iterdir())}")
        else:
            print(f"DEBUG: /scan directory does not exist")
        
        print(f"DEBUG: Looking for file at: {file_path}")
        print(f"DEBUG: File exists: {file_path.exists()}")
        
        if not file_path.exists():
            container_duration_ms = int((time.time() - container_start_time) * 1000)
            print(json.dumps({
                'safe': True,
                'threats': [],
                'scanTime': datetime.utcnow().isoformat(),
                'scanDurationMs': 0,  # No actual scanning
                'containerDurationMs': container_duration_ms,  # Total container time
                'fileSize': 0,
                'fileName': file_path.name,
                'scanEngine': 'container_ensemble',
                'error': 'File not found'
            }))
            return
        
        # Initialize scanner (this is overhead, not pure scanning time)
        print("DEBUG: Initializing ensemble scanner...")
        scanner = EnsembleScanner()
        await scanner.initialize()
        print("DEBUG: Ensemble scanner initialized successfully")
        
        # Perform scan
        print("DEBUG: Starting scan...")
        result = await scanner.scan(file_path)
        print("DEBUG: Scan completed")
        
        # Get the pure scanning time from the ensemble scanner result
        pure_scan_duration_ms = result.scan_duration_ms or 0
        
        # Calculate total container duration
        container_duration_ms = int((time.time() - container_start_time) * 1000)
        
        print(f"DEBUG: Pure scanning time (from ensemble): {pure_scan_duration_ms}ms")
        print(f"DEBUG: Total container time (with all overhead): {container_duration_ms}ms")
        
        # Prepare response with both timing metrics
        response = {
            'safe': result.safe,
            'threats': result.threats,
            'scanTime': result.scan_time.isoformat(),
            'scanDurationMs': pure_scan_duration_ms,  # Pure scanning time (excluding initialization)
            'containerDurationMs': container_duration_ms,  # Total container time including all overhead
            'fileSize': result.file_size,
            'fileName': result.file_name,
            'scanEngine': result.scan_engine
        }
        
        if result.error:
            response['error'] = result.error
        
        # Output JSON result
        print(json.dumps(response))
        
    except Exception as e:
        # Error response
        container_duration_ms = int((time.time() - container_start_time) * 1000) if container_start_time else 0
        error_response = {
            'safe': True,
            'threats': [],
            'scanTime': datetime.utcnow().isoformat(),
            'scanDurationMs': 0,  # No successful scanning
            'containerDurationMs': container_duration_ms,  # Total container time
            'fileSize': file_path.stat().st_size if file_path and file_path.exists() else 0,
            'fileName': file_path.name if file_path else 'unknown',
            'scanEngine': 'container_ensemble',
            'error': str(e)
        }
        print(json.dumps(error_response))
        print(f"ERROR: {str(e)}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main()) 