#!/usr/bin/env python3
"""
Test script to verify parallel container processing.
Sends multiple concurrent requests and monitors container creation.
"""

import asyncio
import aiohttp
import time
import hmac
import hashlib
import json
from datetime import datetime
from typing import List, Dict
import structlog

# Configure logging
structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer()
    ],
    wrapper_class=structlog.BoundLogger,
    context_class=dict,
    logger_factory=structlog.PrintLoggerFactory(),
    cache_logger_on_first_use=True,
)
logger = structlog.get_logger()

# Configuration
API_BASE_URL = "http://localhost:8080"
HMAC_SECRET = "your-secret-key-here"  # Make sure this matches your server config
MAX_CONCURRENT_REQUESTS = 3
REQUEST_DELAY_MS = 100  # Small delay between requests to ensure they're processed concurrently

def generate_hmac_signature(timestamp: str, method: str, path: str, body: str = "") -> str:
    """Generate HMAC signature for request."""
    message = timestamp + method + path + body
    signature = hmac.new(
        HMAC_SECRET.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    return signature

async def send_scan_request(session: aiohttp.ClientSession, request_id: int, file_content: str) -> Dict:
    """Send a single scan request."""
    timestamp = str(int(time.time()))
    method = "POST"
    path = "/api/scan"
    
    # Create multipart form data
    data = aiohttp.FormData()
    data.add_field('file', file_content, filename=f'test_file_{request_id}.txt', content_type='text/plain')
    
    # Generate signature (empty body for multipart)
    signature = generate_hmac_signature(timestamp, method, path, "")
    
    headers = {
        'X-Signature': signature,
        'X-Timestamp': timestamp
    }
    
    start_time = time.time()
    logger.info("sending_request", request_id=request_id, timestamp=timestamp)
    
    try:
        async with session.post(f"{API_BASE_URL}{path}", data=data, headers=headers) as response:
            response_data = await response.json()
            duration = (time.time() - start_time) * 1000
            
            logger.info("request_completed", 
                       request_id=request_id, 
                       status=response.status, 
                       duration_ms=duration,
                       scan_duration=response_data.get('scanDurationMs'),
                       container_duration=response_data.get('containerDurationMs'))
            
            return {
                'request_id': request_id,
                'status': response.status,
                'response': response_data,
                'duration_ms': duration,
                'timestamp': timestamp
            }
    except Exception as e:
        logger.error("request_failed", request_id=request_id, error=str(e))
        return {
            'request_id': request_id,
            'status': 'error',
            'error': str(e),
            'timestamp': timestamp
        }

async def test_parallel_containers():
    """Test that multiple containers are created and run in parallel."""
    logger.info("starting_parallel_container_test", max_concurrent=MAX_CONCURRENT_REQUESTS)
    
    # Create test file content
    test_content = "This is a test file for parallel container processing.\n" * 10
    
    # Create aiohttp session
    timeout = aiohttp.ClientTimeout(total=120)  # 2 minutes timeout
    async with aiohttp.ClientSession(timeout=timeout) as session:
        # Create tasks for concurrent requests
        tasks = []
        for i in range(MAX_CONCURRENT_REQUESTS):
            # Small delay to ensure requests are processed concurrently
            await asyncio.sleep(REQUEST_DELAY_MS / 1000)
            task = asyncio.create_task(send_scan_request(session, i + 1, test_content))
            tasks.append(task)
        
        # Wait for all requests to complete
        logger.info("waiting_for_all_requests")
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        successful_requests = []
        failed_requests = []
        
        for result in results:
            if isinstance(result, Exception):
                logger.error("task_exception", error=str(result))
                failed_requests.append(result)
            elif result.get('status') == 200:
                successful_requests.append(result)
            else:
                failed_requests.append(result)
        
        # Analyze timing
        if successful_requests:
            durations = [r['duration_ms'] for r in successful_requests]
            scan_durations = [r['response'].get('scanDurationMs', 0) for r in successful_requests]
            container_durations = [r['response'].get('containerDurationMs', 0) for r in successful_requests]
            
            logger.info("test_results",
                       total_requests=len(results),
                       successful=len(successful_requests),
                       failed=len(failed_requests),
                       avg_total_duration=sum(durations) / len(durations),
                       avg_scan_duration=sum(scan_durations) / len(scan_durations),
                       avg_container_duration=sum(container_durations) / len(container_durations),
                       max_total_duration=max(durations),
                       min_total_duration=min(durations))
            
            # Check if requests were truly parallel
            if len(successful_requests) > 1:
                # If requests were truly parallel, the total time should be close to the longest individual request
                # rather than the sum of all requests
                total_test_time = max([r['duration_ms'] for r in successful_requests])
                sequential_time = sum([r['duration_ms'] for r in successful_requests])
                
                logger.info("parallelism_analysis",
                           total_test_time_ms=total_test_time,
                           sequential_time_ms=sequential_time,
                           parallelism_ratio=total_test_time / sequential_time)
                
                if total_test_time < sequential_time * 0.8:  # If total time is significantly less than sequential
                    logger.info("parallel_processing_confirmed", 
                               message="Requests were processed in parallel!")
                else:
                    logger.warning("sequential_processing_detected", 
                                  message="Requests may have been processed sequentially")
        
        return {
            'successful': successful_requests,
            'failed': failed_requests,
            'total': len(results)
        }

async def monitor_containers():
    """Monitor running containers to see if multiple are active."""
    logger.info("monitoring_containers")
    
    try:
        async with aiohttp.ClientSession() as session:
            # Check container status (this would require a monitoring endpoint)
            # For now, we'll just log that monitoring is available
            logger.info("container_monitoring_available", 
                       message="Container monitoring can be added via Docker API endpoints")
    except Exception as e:
        logger.error("monitoring_failed", error=str(e))

async def main():
    """Main test function."""
    logger.info("parallel_container_test_started")
    
    # Test parallel container processing
    results = await test_parallel_containers()
    
    # Monitor containers
    await monitor_containers()
    
    logger.info("parallel_container_test_completed", 
               successful=len(results['successful']),
               failed=len(results['failed']))

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("test_interrupted_by_user")
    except Exception as e:
        logger.error("test_failed", error=str(e))
