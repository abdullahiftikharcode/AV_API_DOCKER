# Log Capture Fix for Linux vs Windows Docker Differences

## Problem Description

The original issue was that the virus scanning API worked correctly on Windows (Docker Desktop) but failed on Linux servers. The root cause was a fundamental difference in how Docker handles logging between these platforms:

- **Windows (Docker Desktop)**: Automatically forwards child container logs to parent containers
- **Linux Server**: Treats parent and child containers as completely separate entities

This caused the API to receive empty logs (`"logs": ""`) from child containers on Linux, resulting in 500 errors because the JSON scan results couldn't be parsed.

## Solution Implemented

### 1. **Real-time Log Streaming** (`docker_client.py`)
- Added `stream_container_logs()` method that continuously monitors container output
- Captures logs every 100ms during container execution
- Ensures logs are captured regardless of platform differences

### 2. **Multi-layered Fallback System** (`container_manager.py`)
- **Primary**: Streaming log capture during execution
- **Secondary**: Standard Docker API log retrieval
- **Tertiary**: Real-time log capture during execution
- **Final**: Direct Docker CLI command execution

### 3. **Enhanced Log Parsing**
- Improved JSON detection in log streams
- Better handling of multi-line JSON output
- Robust error handling for malformed logs

## Files Modified

1. **`app/scanner/docker_client.py`**
   - Added `stream_container_logs()` method
   - Added `stream_container_logs_async()` method

2. **`app/scanner/container_manager.py`**
   - Modified `wait_for_container_completion()` method
   - Added `capture_container_logs_during_execution()` method
   - Implemented multi-layered fallback system

3. **`test_log_capture.py`** (new)
   - Test script to verify the fix works

## How It Works

### Before (Windows-only):
```
Parent Container → Child Container → Logs automatically forwarded → JSON parsed
```

### After (Cross-platform):
```
Parent Container → Child Container → Real-time log streaming → Multiple fallbacks → JSON parsed
```

The new system:
1. **Streams logs in real-time** during container execution
2. **Falls back to standard methods** if streaming fails
3. **Captures logs during execution** as additional safety
4. **Uses Docker CLI directly** as final fallback

## Testing the Fix

### 1. **Run the Test Script**
```bash
python3 test_log_capture.py
```

This will test the new log capture functionality with a simple test container.

### 2. **Test with Real Scan**
```bash
# Use your existing test client
python3 test_hmac_client.py --file test_file.txt
```

### 3. **Check Logs**
```bash
# Check parent container logs
docker logs docker-virus-scanner-1

# Check child container logs (if they exist)
docker ps -a
docker logs <child_container_id>
```

## Expected Results

### Before Fix (Linux):
```
{"logs": "", "event": "container_logs", "timestamp": "..."}
{"logs": "", "event": "no_json_found", "timestamp": "..."}
{"method": "POST", "url": "...", "status_code": 500, "event": "request_processed"}
```

### After Fix (Linux):
```
{"logs": "Starting scan...\n{\"safe\": true, \"threats\": [], ...}", "event": "container_logs", "timestamp": "..."}
{"result_data": {...}, "event": "json_found", "timestamp": "..."}
{"method": "POST", "url": "...", "status_code": 200, "event": "request_processed"}
```

## Benefits

1. **Cross-platform compatibility**: Works on both Windows and Linux
2. **Reliable log capture**: Multiple fallback methods ensure logs are captured
3. **Real-time monitoring**: Logs are captured during execution, not just after
4. **Robust error handling**: Graceful degradation if any method fails
5. **Performance**: Minimal overhead with efficient streaming

## Troubleshooting

### If logs are still empty:
1. Check if the scanner container is actually producing output
2. Verify the `/start.sh` script in the scanner container
3. Check container permissions and environment variables
4. Run the test script to isolate the issue

### If JSON parsing fails:
1. Check the actual log output format
2. Verify the scanner is outputting valid JSON
3. Check for encoding issues in the logs

## Deployment

1. **Update the files** with the new code
2. **Restart the API container** to load the changes
3. **Test with a simple scan** to verify the fix
4. **Monitor logs** to ensure proper operation

## Future Improvements

1. **Centralized logging**: Implement structured logging across all containers
2. **Log aggregation**: Use tools like Fluentd or ELK stack
3. **Metrics collection**: Track log capture success rates
4. **Performance optimization**: Fine-tune streaming intervals based on usage patterns
