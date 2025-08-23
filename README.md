# Advanced Malware Analysis API

A comprehensive, production-ready malware analysis API with multi-engine detection, static analysis, HMAC authentication, and threat intelligence integration.

## Features

- **Multi-Engine Detection System**:
  - **Bytescale API** (Fast cloud-based analysis, first priority for supported file types)
  - **ClamAV** (Primary signature-based detection using direct clamscan, ~45% weight)
  - **YARA Rules** (Pattern matching, ~25% weight)  
  - **ML/Entropy Analysis** (Statistical file analysis, ~15% weight)
  - **MalwareBazaar API** (Threat intelligence lookup, ~15% weight)
  - **Ensemble Voting** (Weighted combination for optimal accuracy)

- **Advanced Static Analysis**:
  - **Advanced Static Analysis** (Windows/Linux/macOS executables, Android APKs, documents)
  - **API/DLL Analysis** (Function imports, suspicious API calls)
  - **Behavioral Analysis** (Network indicators, embedded executables)
  - **Document Analysis** (URLs, IPs, macros, embedded objects)
  - **Android Analysis** (Permissions, activities, services, receivers)

- **Threat Intelligence**:
  - **Bytescale API** (Fast cloud-based malware detection)
  - **MalwareBazaar API** (Hash-based threat lookup)
  - **Multi-Vendor Detection** (ReversingLabs, DocGuard, Spamhaus, etc.)
  - **YARA Rule Matching** (Custom and community rules)
  - **Behavioral Indicators** (Tags and IOCs)
  - **Real-time Threat Data** (First seen dates, delivery methods)

- **User Interface**:
  - **RESTful API** (Programmatic access with HMAC authentication)
  - **Real-time Results** (Live scan progress and detailed reports)
  - **Test Clients** (Provided Python scripts for easy testing)
  - **Python Code Execution** (Secure container-based execution without storing source code)

- **Production-Ready Features**:
  - **Container Isolation** (Secure scanning environment)
  - **HMAC Authentication** (Request signing with SHA-256 signatures)
  - **Network Security** (Restricted internet access for threat intelligence only)
  - **Health Monitoring** (System status and resource usage)
  - **Structured Logging** (JSON format with detailed debugging)
  - **Graceful Degradation** (Offline mode support)
  - **Resource Management** (Memory limits, timeouts, cleanup)
  - **Precise Timing Metrics** (Separate scanning and container overhead measurements)

## Bytescale Integration

The system includes **Bytescale API** integration as the first line of defense for supported file types. This provides:

- **Fast Cloud-Based Analysis**: Leverages Bytescale's advanced malware detection capabilities
- **Immediate Results**: Returns safe/unsafe status before proceeding to local scanners
- **File Size Handling**: Skips files larger than `BYTESCALE_MAX_FILE_SIZE_MB` (default 500MB) and falls back to local engines
- **Fallback Support**: Seamlessly falls back to ensemble scanning if Bytescale fails
- **High Confidence**: Provides detailed threat information when malware is detected

### Configuration
```bash
# Bytescale API (set in your .env)
BYTESCALE_API_KEY=your-bytescale-api-key
BYTESCALE_ACCOUNT_ID=your-bytescale-account-id
BYTESCALE_ENABLED=true
BYTESCALE_MAX_FILE_SIZE_MB=500
BYTESCALE_TIMEOUT=30
```

### How It Works
1. **Direct Streaming**: The uploaded file is streamed directly into a fresh, isolated child container (not written to the API container)
2. **Bytescale First**: The child container uploads to Bytescale for rapid analysis when eligible
3. **Immediate Response**: If Bytescale detects malware, results are returned immediately and other scanners are skipped
4. **Fallback**: If Bytescale is ineligible (e.g., size over `BYTESCALE_MAX_FILE_SIZE_MB`) or fails, local ensemble scanning runs
5. **Ensemble Integration**: Local scanners (ClamAV, YARA, ML, MalwareBazaar) run in parallel and results are combined

## ClamAV Implementation

The system now uses **direct clamscan execution** instead of the traditional ClamAV daemon approach for improved performance and reliability.

### Key Benefits
- **🚀 Faster Startup**: Containers start in 2-5 seconds instead of 30-120 seconds
- **💾 Lower Memory**: No persistent daemon process consuming memory
- **🔒 Better Security**: No persistent daemon process or socket vulnerabilities
- **⚡ Immediate Availability**: ClamAV scanning available immediately after container start
- **🔄 Process Isolation**: Each scan runs clamscan independently

### How It Works
1. **Container Initialization**: Virus databases copied to `/tmp/clamav/db/`
2. **Binary Verification**: clamscan binary availability confirmed
3. **Direct Execution**: Each scan runs `clamscan --database=/tmp/clamav/db/ file`
4. **No Daemon**: No socket waiting, no daemon startup delays
5. **Clean Results**: Same threat detection capabilities with faster performance

### Performance Improvements
- **Startup Time**: **90-95% faster** (from 30-120s to 2-5s)
- **Memory Usage**: **Lower** (no persistent daemon)
- **Reliability**: **Higher** (no socket connection issues)
- **Security**: **Better** (no persistent daemon process)

## Python Code Execution

The system now supports **secure Python code execution** using the piping method, where Python code is executed in isolated containers without storing the source code on disk.

### Key Features
- **Source Code Protection**: Your Python code never touches the container's filesystem
- **Secure Execution**: Code runs in isolated containers with restricted permissions
- **Immediate Cleanup**: Temporary files are deleted immediately after execution
- **Threat Detection**: Built-in pattern detection for potentially malicious code
- **Real-time Output**: Capture stdout/stderr from code execution

### How It Works
1. **Code Piping**: Python code is piped directly into the container via stdin
2. **Temporary Execution**: Code is written to `/tmp/script.py`, executed, then immediately deleted
3. **Isolated Environment**: Each execution runs in a fresh, isolated container
4. **Threat Analysis**: Output is analyzed for suspicious patterns and execution results
5. **Secure Cleanup**: Container and all temporary files are destroyed after execution

### API Endpoint
```bash
POST /api/execute-python
Content-Type: application/json

{
  "code": "print('Hello, World!')",
  "timeout": 300
}
```

### Security Features
- **Pattern Detection**: Automatically flags dangerous imports and functions
- **Resource Limits**: Configurable memory and CPU limits per execution
- **Network Isolation**: Containers have restricted network access
- **Timeout Protection**: Configurable execution timeouts prevent hanging
- **Code Size Limits**: Maximum 1MB code size to prevent abuse

### Example Usage
```bash
# Execute Python code directly
python test_python_execution.py --url http://localhost:8080 --code "print('Hello from container!')"

# Execute Python code from file
python test_python_execution.py --url http://localhost:8080 --file my_script.py
```

## Requirements

- Python 3.11+
- Docker and Docker Compose
- **10GB RAM minimum** (for concurrent container operation)
- **4 CPU cores minimum** (2 for scanning containers + 2 for API)
- Internet connection (for Bytescale API and MalwareBazaar threat intelligence)
- ClamAV virus definitions (automatically configured in Docker)
- **PyTorch CPU-only** (optimized for containerized environments, no GPU required)

## Supported File Types

The system now supports a comprehensive range of file types for analysis:

### **Executables and System Files**
- **Windows**: Windows PE (.exe, .dll, .sys, .drv, .cpl, .scr), Installers (.msi, .msix, .msixbundle, .msp, .mst)
- **Command Line**: .com, .bat, .cmd, .pif, .reg, .rgs
- **Scripts**: .vbs, .vbe, .js, .jse, .ws, .wsf, .wsc, .wsh, .ps1, .ps1xml, .ps2, .ps2xml
- **Python**: .py, .pyc, .pyo
- **Mobile**: Android (.apk), iOS (.ipa), macOS (.app, .dmg), Linux (.deb, .rpm, .pkg)
- **Linux/Unix**: .elf, .out, .bin, .so, .ko, .o, .a, .lib, .dylib, .bundle

### **Scripts and Interpreted Files**
- **Shell Scripts**: .sh, .bash, .csh, .tcsh, .ksh, .zsh
- **Programming**: .pl, .pm, .rb, .php, .php3, .asp, .aspx, .jsp, .jsx
- **Web**: .html, .htm, .xhtml, .xml, .xslt, .css, .scss, .sass
- **Other**: .awk, .sed, .perl, .tcl, .lua, .r, .m, .scala, .go, .rs, .swift

### **Documents and Office Files**
- **Microsoft Office**: .doc, .docx, .docm, .xls, .xlsx, .xlsm, .ppt, .pptx, .pptm
- **Other Documents**: .pdf, .rtf, .txt, .csv, .log, .ini, .cfg, .conf, .config

### **Archives and Compressed Files**
- **Common**: .zip, .rar, .7z, .tar, .gz, .bz2, .xz, .cab, .iso, .udf
- **Advanced**: .tgz, .tbz2, .txz, .lzma, .lz, .lzo, .lz4, .zst

### **Media and Binary Files**
- **Video**: .mp3, .mp4, .avi, .mkv, .mov, .wmv, .flv, .webm, .m4v
- **Images**: .jpg, .jpeg, .png, .gif, .bmp, .tiff, .svg, .ico, .cur
- **Audio**: .wav, .flac, .aac, .ogg, .wma, .m4a, .opus

### **Development and Source Files**
- **C/C++**: .c, .cpp, .cc, .cxx, .h, .hpp, .hh, .hxx
- **Other Languages**: .java, .cs, .vb, .pas, .pascal, .f, .f90, .f95, .f03, .f08, .for, .ftn
- **Assembly**: .asm, .s, .S, .inc, .def, .rc, .res, .ico, .cur, .ani

### **Network and Web Files**
- **Shortcuts**: .url, .lnk, .webloc, .website
- **Web Files**: .htm, .html, .shtml, .xhtml
- **Server Scripts**: .cgi, .pl, .py, .php, .jsp, .asp, .aspx, .ashx, .asmx

### **Database and Data Files**
- **Databases**: .db, .sqlite, .sql, .csv, .tsv
- **Data Formats**: .json, .xml, .yaml, .yml
- **Configuration**: .ini, .cfg, .conf, .config, .properties, .env, .bashrc, .profile

### **Other Supported Extensions**
- **System Files**: .chm, .hlp, .inf, .ins, .ocx, .tlb, .olb
- **Specialized**: .gadget, .widget, .workflow, .applescript, .scpt, .scptd, .osa
- **Legacy**: .seed, .spr, .sct, .vdl, .vdo, .vxd, .sys, .386
- **And many more**: Including all extensions from your comprehensive list

**Total Supported Extensions**: 200+ file types covering executables, scripts, documents, archives, media, source code, and system files.

## Quick Start

### 1. **Clone the Repository**:
```bash
git clone <repository-url>
cd API_AV
```

### 2. **Build the Child Container Image**:
```bash
# First, build the scanner container image that will be used for child containers
docker build -f docker/Dockerfile.scanner -t virus-scanner-scanner:latest .
```

### 3. **Start the Analysis System**:
```bash
# Start the main API server
cd docker
docker-compose up -d --build
```

### 4. **Access the System**:

**API Interface**:
```bash
# Health check (no authentication required)
curl http://localhost:8080/health

# Scan a file via API (requires HMAC authentication)
# See "HMAC Authentication" section below for signed requests
curl -X POST -F "file=@test_files/malware_sample.exe" \
  -H "X-Signature: your-hmac-signature" \
  -H "X-Timestamp: $(date +%s)" \
  http://localhost:8080/api/scan
```

### 5. **Test with Sample Files**:
```bash
# Use the provided test client for authenticated requests
python test_hmac_client.py --file test_files/instagram.apk
python test_hmac_client.py --file test_files/document.pdf
python test_hmac_client.py --file test_files/suspicious.exe

# Or test the health endpoint (no authentication required)
python test_hmac_client.py --health
```

## HMAC Authentication

The API uses HMAC-SHA256 authentication to secure all scan requests. Health endpoints are exempt from authentication.

### Configuration

Set your secret key in the `.env` file:

1. Copy the example configuration:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` and set your secret key:
   ```bash
   # HMAC Authentication Secret Key
   HMAC_SECRET_KEY=your-actual-secret-key-here
   ```

**Important**: 
- Never commit the `.env` file to version control
- Use a strong, random secret key in production
- The `.env` file is automatically loaded by the Docker container

### Creating Signed Requests

Each request must include two headers:
- `X-Signature`: HMAC-SHA256 signature of the request
- `X-Timestamp`: Unix timestamp when the request was created

**Message Format**: `timestamp + method + path + body`

For file uploads (multipart/form-data), use an empty string for the body in signature calculation.

### Python Example

```python
import hmac
import hashlib
import time
import requests

def create_signed_request(secret_key, method, path, body=""):
    timestamp = str(int(time.time()))
    message = timestamp + method + path + body
    signature = hmac.new(
        secret_key.encode(),
        message.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return {
        'X-Signature': signature,
        'X-Timestamp': timestamp
    }

# Example usage
secret_key = "your-secret-key-here"
headers = create_signed_request(secret_key, "POST", "/api/scan", "")

with open("test_file.pdf", "rb") as f:
    response = requests.post(
        "http://localhost:8080/api/scan",
        files={"file": f},
        headers=headers
    )
```

### Test Scripts

Use the provided test scripts for easy testing:

```bash
# Test with file upload
python test_hmac_client.py --file path/to/file.pdf

# Test health endpoint (no authentication)
python test_hmac_client.py --health

# Simple signature verification test
python simple_hmac_test.py
```

### Security Features

- **Timestamp validation**: Requests older than 5 minutes are rejected
- **Signature verification**: All requests must have valid HMAC signatures
- **Replay protection**: Timestamp prevents replay attacks
- **Secure comparison**: Constant-time signature comparison prevents timing attacks

## API Usage

### Scan File Endpoint

```http
POST /api/scan
Content-Type: multipart/form-data
```

**Parameters**:
- `file`: The file to scan (max size: 1.5GB)

**Request Headers** (Required for authentication):
- `X-Signature`: HMAC-SHA256 signature of the request
- `X-Timestamp`: Unix timestamp when the request was created

**Response Fields**:
- `scanDurationMs`: **Pure scanning time** in milliseconds (time spent by ClamAV, YARA, ML, and MalwareBazaar engines, excluding initialization)
- `containerDurationMs`: **Total container time** in milliseconds (includes container startup, scanner initialization, virus definition loading, and scanning)
- `scanTime`: Timestamp when the scan completed
- `safe`: Boolean indicating if the file is safe
- `threats`: List of detected threats (empty if safe)
- `fileSize`: File size in bytes
- `fileName`: Original filename
 - `scanEngine`: Scanning engine used ("bytescale" when Bytescale returns early, otherwise "ensemble")

**Timing Metrics Explanation**:
- The difference between `containerDurationMs` and `scanDurationMs` shows the overhead of container initialization, virus definition loading, and cleanup
- `scanDurationMs` represents the actual time spent analyzing the file content
- Both metrics help identify performance bottlenecks and optimize scanning efficiency

**Example Request**:
```bash
# Using the test client (recommended)
python test_hmac_client.py --file /path/to/file.pdf

# Manual curl with HMAC signature
SECRET_KEY="your-secret-key-here"
TIMESTAMP=$(date +%s)
MESSAGE="${TIMESTAMP}POST/api/scan"
SIGNATURE=$(echo -n "$MESSAGE" | openssl dgst -sha256 -hmac "$SECRET_KEY" -hex | cut -d' ' -f2)

curl -X POST "http://localhost:8080/api/scan" \
  -H "Content-Type: multipart/form-data" \
  -H "X-Signature: $SIGNATURE" \
  -H "X-Timestamp: $TIMESTAMP" \
  -F "file=@/path/to/file.pdf"
```

**Example Response (Clean File)**:
```json
{
  "safe": true,
  "threats": [],
  "scanTime": "2025-08-12T13:41:01.375293",
  "scanDurationMs": 1263,
  "containerDurationMs": 1953,
  "fileSize": 58,
  "fileName": "clean_file.txt",
  "scanEngine": "ensemble"
}
```

**Example Response (Bytescale Detection)**:
```json
{
  "safe": false,
  "threats": [
    "Bytescale detected viruses: Win.Test.EICAR_HDB-1"
  ],
  "scanTime": "2025-08-14T20:21:37.516197",
  "scanDurationMs": 1726,
  "containerDurationMs": 2384,
  "fileSize": 68,
  "fileName": "eicar.txt",
  "scanEngine": "bytescale"
}
```

**Example Response (Malware Detected)**:
```json
{
  "safe": false,
  "threats": [
    "Malware: Document.Trojan.Heuristic (ReversingLabs)",
    "Suspicious: YARA: Sus_Obf_Enc_Spoof_Hide_PE",
    "Known malicious file: W2.pdf"
  ],
  "scanTime": "2025-08-09T17:48:35.689177",
  "scanDurationMs": 2688,
  "containerDurationMs": 5123,
  "fileSize": 131320,
  "fileName": "suspicious_document.pdf",
  "scanEngine": "ensemble",
  "details": {
    "malwarebazaar_signature": null,
    "vendor_detections": ["Document.Trojan.Heuristic (ReversingLabs)"],
    "yara_rules": ["Sus_Obf_Enc_Spoof_Hide_PE"],
    "behavioral_indicators": ["Behavioral indicator: pdf"],
    "delivery_method": "web_download",
    "first_seen": "2025-08-09 16:22:24",
    "origin_country": "GB"
  }
}
```

### Health Check Endpoint

```http
GET /health
```

**Example Request**:
```bash
curl "http://localhost:8080/health"
```

**Example Response**:
```json
{
  "status": "healthy",
  "memory": {
    "total_mb": 8192,
    "used_mb": 4096,
    "available_mb": 4096,
    "usage_percent": 50,
    "process_rss_mb": 2048,
    "process_vms_mb": 3072
  },
  "activeScanners": 1,
  "memoryPressure": null
}
```

## Configuration

Key configuration options (managed via Docker Compose and source code):

```bash
# Server Configuration
PORT=8080
MAX_FILE_SIZE_MB=1536
SCAN_TIMEOUT_SECONDS=300
LOG_LEVEL=INFO
MAX_CONCURRENT_SCANS=6

# Container Resource Configuration
MEMORY_LIMIT_MB=3000           # Per child container (3GB each)
CHILD_CONTAINER_MEMORY=4g      # Docker memory limit per container
CHILD_CONTAINER_CPU=1.0        # CPU cores per container
# ClamAV configuration (direct clamscan - no daemon)

# Container Configuration
TMPFS_SIZE=400m        # In-memory filesystem for temporary files
# ClamAV databases directory (direct clamscan usage)
CLAMAV_DB_DIR=/tmp/clamav/db
SCAN_DIRECTORY=/scan   # Isolated scan directory

# File Handling
# Files are streamed directly to child containers into /scan. The API container never writes uploaded files to disk.

# Docker Settings
RESTART_POLICY=unless-stopped
NETWORK_MODE=bridge    # Required for MalwareBazaar API access
DNS_SERVERS=8.8.8.8,1.1.1.1  # Reliable DNS resolution
```

### MalwareBazaar API Configuration

The system includes pre-configured MalwareBazaar API keys for threat intelligence:

```python
# Located in app/scanner/malwarebazaar_scanner.py
self.api_keys = [
    "cdc2a1a430937339cea4f97de623948d396d9835e698929d",  # Primary key
    "4135e9d27428e33be0c8eecd6b71bcb560aa7cc65fd709a1"   # Fallback key
]
```

**Features**:
- **Automatic fallback**: If primary key fails, secondary key is used
- **Offline mode**: System works without internet access
- **Rate limiting**: Respectful API usage
- **Vendor intelligence**: Multiple security vendor detections
- **YARA integration**: Rule matching from MalwareBazaar database

### Static Analysis Configuration

Advanced static analysis capabilities are provided through integrated scanning engines:

**Supported Analysis Types**:
- **Executable Analysis** - PE, ELF, Mach-O file analysis
- **Document Analysis** - PDF, Office files with embedded content detection
- **Archive Analysis** - ZIP, RAR, 7Z with embedded executable detection
- **Network Indicators** - URL, IP, and domain extraction
- **Behavioral Analysis** - Suspicious patterns and IOCs

## Directory Structure

```
API_AV/
├── app/
│   ├── scanner/         # Multi-engine scanning system
│   │   ├── base.py      # Base scanner interface with timing support
│   │   ├── clamav.py    # ClamAV signature-based detection (direct clamscan)
│   │   ├── yara_scanner.py  # YARA pattern matching
│   │   ├── ml_detector.py   # ML/Entropy analysis
│   │   ├── malwarebazaar_scanner.py  # Threat intelligence API
│   │   ├── ensemble.py  # Weighted ensemble voting with precise timing
│   │   ├── container_manager.py  # Docker container management
│   │   ├── docker_client.py      # Low-level Docker API
│   │   └── scan_worker.py        # Container-based scan execution
│   ├── middleware/      # Authentication and request processing
│   │   ├── __init__.py  # Middleware package exports
│   │   └── hmac_auth.py # HMAC authentication middleware
│   ├── routes/          # FastAPI REST endpoints
│   ├── utils/           # Helper utilities and logging
│   ├── config.py        # System configuration with HMAC settings
│   └── main.py         # Application entry point

├── docker/             # Container configuration
│   ├── docker-compose.yml  # Service orchestration
│   ├── Dockerfile.scanner  # Multi-engine scanner container
│   ├── requirements-*.txt  # Dependency specifications
│   └── # Qu1cksc0pe removed
├── # Qu1cksc0pe removed
├── rules/             # YARA detection rules
├── data/              # Runtime data and logs
├── test_files/        # Sample files for testing
├── test_hmac_client.py    # HMAC authentication test client
├── simple_hmac_test.py    # Simple HMAC signature verification test
├── test_no_hmac.py        # Test script for unauthenticated requests
├── HMAC_AUTHENTICATION.md # Detailed HMAC authentication documentation
└── README.md          # This documentation
```

## System Resource Usage

The comprehensive analysis system requires **10GB RAM** for concurrent operation:

**Per Child Container (2 concurrent containers):**
- **Memory**: 4GB per container (8GB total for scanning)
- **CPU**: 1 core per container (2 cores total for scanning)
- **ClamAV virus definitions**: 1-1.5GB (virus databases for direct clamscan)
- **YARA rules**: 200-400MB (pattern matching rules)
- **ML models**: 300-500MB (machine learning analysis)
- **Container overhead**: 500MB-1GB (Docker + isolation)

**Main API Container:**
- **Memory**: 2GB (FastAPI + orchestration + threat intelligence)
- **CPU**: 1-2 cores (request handling + container management)

**Total System Requirements:**
- **CPU**: 4 cores minimum (2 for scanning containers + 2 for API)
- **RAM**: 10GB minimum (8GB for containers + 2GB for API)
- **Storage**: 5GB for virus definitions and ML models

**Network Usage**:
- **MalwareBazaar API**: ~1-5KB per query (hash lookups)
- **Selective internet access**: Only threat intelligence APIs allowed
- **Offline mode**: Graceful degradation when network unavailable

## Performance Optimization

1. **Multi-Engine Analysis**:
   - **Parallel scanning**: All engines run concurrently
   - **Weighted ensemble**: Optimized confidence scoring
   - **Early termination**: Fast hash-based threat intelligence lookup
   - **Selective analysis**: Engine selection based on file type

2. **Container-based Isolation**:
   - **Secure scanning environment**: Complete process isolation
   - **Resource limits**: Memory and CPU constraints per scan
   - **Automatic cleanup**: Container destruction after analysis
   - **5-minute timeout**: Protection against infinite analysis
   - **Fast ClamAV startup**: Direct clamscan execution (2-5s vs 30-120s)

3. **Caching and Optimization**:
   - **Docker layer caching**: Optimized build times
   - **Virus definition caching**: ClamAV virus databases preserved
   - **Static analysis caching**: Integrated scanning optimization
   - **Result streaming**: Real-time progress updates

4. **Network and Security**:
   - **Selective internet access**: Only MalwareBazaar API allowed
   - **DNS configuration**: Reliable name resolution
   - **Offline mode**: Graceful degradation without network
   - **API rate limiting**: Respectful threat intelligence usage

## Security Considerations

1. **Authentication and Authorization**:
   - **HMAC-SHA256 signatures**: All scan requests require cryptographic signatures
   - **Timestamp validation**: Requests older than 5 minutes are rejected
   - **Replay protection**: Timestamp-based replay attack prevention
   - **Secure comparison**: Constant-time signature verification
   - **Health endpoint exemption**: Monitoring endpoints remain accessible

2. **Container Isolation**:
   - **Complete process isolation**: Each scan runs in a separate container
    - **Direct streaming**: Files stream directly to child containers (no writes in API container)
    - **Temporary filesystems**: In-memory `tmpfs` for sensitive data
    - **Network restrictions**: Only MalwareBazaar and Bytescale API access allowed
   - **Resource limits**: CPU and memory constraints enforced
   - **Automatic cleanup**: Container destruction after analysis

3. **File Handling**:
    - **Direct streaming to child containers**: No storage in the API container
    - **No persistent storage**: Files deleted immediately after scanning in child containers
   - **Size validation**: 1.5GB upload limit enforced
   - **Type validation**: File format verification before analysis
   - **Path sanitization**: Protection against directory traversal

4. **Network Security**:
   - **Application-level filtering**: Only approved domains allowed
   - **DNS restrictions**: Trusted DNS servers (8.8.8.8, 1.1.1.1)
   - **TLS encryption**: Secure API communications
   - **Offline mode**: System functions without internet access
   - **Rate limiting**: Protection against API abuse

5. **Analysis Security**:
   - **Static analysis only**: No code execution in containers
   - **Timeout protection**: 5-minute scan limit prevents resource exhaustion
   - **Memory isolation**: Separate memory space per analysis
   - **Error containment**: Failures don't affect other scans
   - **Audit logging**: Complete scan activity tracking

## Recent Changes (v3.2 - API-Only Security & Performance)

### Major Enhancements
- **✅ API-Only Architecture** - Streamlined API-focused design without frontend dependencies
- **✅ HMAC Authentication** - HMAC-SHA256 request signing with replay protection
- **✅ Precise Timing Metrics** - Separate measurement of pure scanning vs container overhead
- **✅ Advanced Static Analysis** - Comprehensive static analysis for executables, APKs, and documents
- **✅ MalwareBazaar API** - Real-time threat intelligence with multi-vendor detection
- **✅ Enhanced Security** - Authentication, selective internet access and network isolation
- **✅ Improved Parsing** - Detailed threat descriptions from vendor intelligence
- **✅ Increased File Size Limit** - Now supports files up to 1.5GB
- **✅ ClamAV Optimization** - Direct clamscan execution for 90-95% faster startup
- **✅ Direct File Streaming** - Files stream directly to child containers; API container never stores uploads

### Current Detection Engines (Weighted Ensemble)
1. **ClamAV** (40% weight) - Signature-based detection using direct clamscan
2. **MalwareBazaar** (25% weight) - Threat intelligence and vendor detections
3. **YARA** (20% weight) - Pattern matching rules
4. **ML/Entropy** (10% weight) - Statistical analysis
5. **Advanced Static Analysis** (integrated into other engines) - Comprehensive static analysis

### New Capabilities
- **🔐 HMAC Authentication** - Cryptographic request signing with timestamp validation
- **⏱️ Performance Metrics** - Detailed timing analysis for scanning optimization
- **📱 Android APK Analysis** - Permissions, activities, services, and behavioral analysis
- **📄 Document Analysis** - PDF, Office files with URL/IP extraction and macro detection
- **🔍 Advanced Static Analysis** - API calls, DLL imports, embedded executables
- **🌐 Threat Intelligence** - Real-time hash lookups with vendor correlation
- **🎯 Behavioral Indicators** - YARA rules, suspicious patterns, and IOCs
- **💻 Multi-Platform Support** - Windows PE, Linux ELF, macOS Mach-O analysis
- **📏 Large File Support** - Handle files up to 1.5GB for comprehensive analysis

### Architecture Improvements
- **API-Only Design** - Removed frontend dependencies for streamlined deployment
- **Concurrent Container Support** - 6 parallel scanning containers (3GB RAM, 1 CPU each)
- **Authentication Middleware** - HMAC-SHA256 signature verification with FastAPI integration
- **Timing Precision** - Separate measurement of pure scanning vs initialization overhead
- **Container Optimization** - Docker layer caching for faster builds
- **Network Security** - Application-level restrictions for API access only
- **Resource Management** - Optimized for concurrent operation (10GB total RAM)
- **Offline Mode** - Graceful degradation when internet unavailable
- **Real-time Processing** - Concurrent engine execution with progress tracking
- **Large File Handling** - Optimized for scanning files up to 1.5GB

## Troubleshooting

### Common Issues

1. **HMAC Authentication Issues**:
   ```bash
   # Test authentication with provided scripts
   python test_hmac_client.py --health
   python simple_hmac_test.py
   
   # Check for 401 errors in logs
   docker logs docker-virus-scanner-1 | grep "hmac_validation"
   
   # Verify secret key configuration
   # Check if .env file exists and contains HMAC_SECRET_KEY
   ls -la .env
   grep HMAC_SECRET_KEY .env
   
   # Test without authentication (should get 401)
   python test_no_hmac.py
   ```

2. **Container won't start**:
   ```bash
   # Check Docker logs
   docker-compose logs virus-scanner
   
   # Restart services
   docker-compose restart
   
   # Rebuild if needed
   docker-compose up --build -d
   ```

3. **MalwareBazaar API not working**:
   ```bash
   # Check network connectivity
   docker exec docker-virus-scanner-1 curl -s https://mb-api.abuse.ch/api/v1/
   
   # Check API key authentication
   docker logs docker-virus-scanner-1 | grep "MalwareBazaar"
   
   # Test offline mode
   # System should work without internet access
   ```

4. **ClamAV scanning issues**:
   ```bash
   # Check clamscan binary availability
   docker exec docker-virus-scanner-1 which clamscan
   
   # Verify virus databases are copied
   docker exec docker-virus-scanner-1 ls -la /tmp/clamav/db/
   
   # Test clamscan directly
   docker exec docker-virus-scanner-1 clamscan --version
   
   # Check container startup logs for ClamAV initialization
   docker logs docker-virus-scanner-1 | grep -i "clamav\|clamscan"
   ```

5. **Static analysis failing**:
   ```bash
   # Check YARA rules installation
   docker exec docker-virus-scanner-1 ls -la /app/rules/
   
   # Test YARA scanner directly
   docker exec docker-virus-scanner-1 python3 -c "from app.scanner.yara_scanner import YARAScanner; print('YARA scanner available')"
   
   # Check ML models
   docker exec docker-virus-scanner-1 ls -la /app/data/ml_models/
   ```

6. **High memory usage**:
   ```bash
   # Monitor container resources
   docker stats
   
   # Check system resources
   curl http://localhost:8080/health
   
   # Adjust container limits in docker-compose.yml
   ```

7. **Scan timeouts or failures**:
   - Default timeout is 5 minutes (300 seconds)
   - Large files (>1GB) may need more time
   - Check container resources and logs
   - Verify file format is supported

8. **Large file upload issues**:
   ```bash
   # Check file size limits
   curl http://localhost:8080/health
   
   # Verify ClamAV virus databases
docker exec docker-virus-scanner-1 ls -la /tmp/clamav/db/
   
   # Check container memory limits
   docker stats docker-virus-scanner-1
   ```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

[Your License Here]

## Support

[Your Support Information] 