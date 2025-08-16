# HMAC Authentication for Virus Scanner API

This document explains how to use HMAC-SHA256 authentication with the Virus Scanner API.

## Overview

The API uses HMAC-SHA256 signatures to authenticate requests. Each request must include:
- `X-Signature`: HMAC-SHA256 signature of the request
- `X-Timestamp`: Unix timestamp when the request was created

## Configuration

Set the following environment variables or update `app/config.py`:

```python
HMAC_SECRET_KEY = "your-secret-key-here"  # Use a strong, random key
HMAC_ENABLED = True
HMAC_TIMESTAMP_TOLERANCE_SECONDS = 300  # 5 minutes
```

## Signature Creation

The signature is created using this formula:

```
message = timestamp + method + path + body
signature = HMAC-SHA256(secret_key, message)
```

### Python Example

```python
import hmac
import hashlib
import time

def create_signature(secret_key, method, path, body=""):
    timestamp = str(int(time.time()))
    message = timestamp + method + path + body
    
    signature = hmac.new(
        secret_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return signature, timestamp

# Example usage
secret_key = "your-secret-key-here"
signature, timestamp = create_signature(secret_key, "POST", "/api/scan", "")

headers = {
    'X-Signature': signature,
    'X-Timestamp': timestamp
}
```

## File Upload Example

For file uploads (multipart/form-data), use an empty string as the body:

```python
import requests

# Create signature with empty body for file uploads
signature, timestamp = create_signature(secret_key, "POST", "/api/scan", "")

headers = {
    'X-Signature': signature,
    'X-Timestamp': timestamp
}

with open('test_file.txt', 'rb') as f:
    files = {'file': f}
    response = requests.post(
        'http://localhost:8080/api/scan',
        files=files,
        headers=headers
    )
```

## Testing

### Run the Simple Test

```bash
python simple_hmac_test.py
```

### Run the Full Client Test

```bash
# Health check (no HMAC required)
python test_hmac_client.py --health

# Scan a file
python test_hmac_client.py --file test_files/clean_file.txt

# Custom server and secret
python test_hmac_client.py --url http://your-server:8080 --secret your-key --file test.txt
```

## Security Notes

1. **Keep the secret key secure**: Store it in environment variables, not in code
2. **Use HTTPS**: HMAC protects against tampering but not eavesdropping
3. **Timestamp validation**: Requests older than 5 minutes (configurable) are rejected
4. **Secure comparison**: The server uses `hmac.compare_digest()` to prevent timing attacks

## Troubleshooting

### Common Errors

- **401 - Missing X-Signature header**: Include the signature header
- **401 - Missing X-Timestamp header**: Include the timestamp header
- **401 - Invalid timestamp format**: Ensure timestamp is a valid Unix timestamp
- **401 - Request timestamp is too old**: Check system clocks are synchronized
- **401 - Invalid signature**: Verify the message format and secret key

### Debug Tips

1. Check that clocks are synchronized between client and server
2. Verify the secret key matches on both sides
3. Ensure the message format is exactly: `timestamp + method + path + body`
4. For file uploads, use an empty string as the body in signature calculation
5. Check that the timestamp is within the tolerance window (default: 5 minutes)

## Endpoints

- `/health` - Health check (HMAC not required)
- `/api/scan` - File scanning (HMAC required)
- `/docs` - API documentation (HMAC not required)
