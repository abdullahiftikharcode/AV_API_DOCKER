import asyncio
import aiohttp
from pathlib import Path
from typing import Optional
from datetime import datetime

from .base import BaseScanner, ScanResult
from ..config import settings


class BytescaleScanner(BaseScanner):
    """Scanner that uses Bytescale API for fast file analysis."""

    def __init__(self):
        super().__init__("bytescale")
        self.api_key = settings.BYTESCALE_API_KEY
        self.account_id = settings.BYTESCALE_ACCOUNT_ID  # Load from environment variable
        self.api_base_url = "https://api.bytescale.com"  # API endpoint
        self.cdn_base_url = "https://upcdn.io"  # CDN endpoint for file access
        self.max_file_size_mb = settings.BYTESCALE_MAX_FILE_SIZE_MB
        self.session: Optional[aiohttp.ClientSession] = None

    async def initialize(self) -> None:
        """Initialize the HTTP session."""
        # Increase timeout and set per-operation timeouts
        timeout = aiohttp.ClientTimeout(
            total=settings.BYTESCALE_TIMEOUT,
            connect=30,         # Connection timeout: 30 seconds
            sock_read=60        # Socket read timeout: 1 minute
        )
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            headers={
                "User-Agent": "API_AV/1.0"
            }
        )
        self.initialized = True

    async def cleanup(self) -> None:
        """Cleanup the HTTP session."""
        if self.session:
            await self.session.close()
            self.session = None
        self.initialized = False

    def _should_skip_file(self, file_path: Path) -> bool:
        """Check if file should be skipped based on size and type restrictions."""
        try:
            # Check file size
            file_size_mb = file_path.stat().st_size / (1024 * 1024)
            if file_size_mb > self.max_file_size_mb:
                print(f"DEBUG: File {file_path} exceeds size limit ({file_size_mb:.2f} MB > {self.max_file_size_mb} MB)")
                return True
            
            # Check file extension against Bytescale's rejected extensions
            file_ext = file_path.suffix.lower().lstrip('.')
            
            # Comprehensive list of extensions that Bytescale doesn't support
            REJECTED_EXTS = {
                "exe","a6p","ac","acr","action","ade","adp","air","apk","app","applescript","application",
                "appx","appxbundle","asp","awk","bas","bash","bat","cab","ccs","cgi","chm","class","cmd",
                "cmp","com","command","cpl","crt","csh","deb","dek","dld","dll","dmg","docm","drv","ds",
                "ebm","elf","emf","esh","ezs","fky","frs","fxp","gadget","gpe","gpu","grp","hlp","hms",
                "hta","htm","html","htx","icd","iim","inf","inf1","ins","inx","ipa","ipf","iso","isp",
                "isu","jar","je","job","jse","jsp","jsx","jtd","kix","ksh","lib","lnk","mcr","mde","mel",
                "mem","mpkg","mpx","mrc","ms","msc","msi","msix","msixbundle","msp","mst","mxe","nsh",
                "obs","ocx","osax","osx","out","ovl","paf","pas","pcd","pex","php","php3","pif","pkg",
                "pl","plsc","pm","prc","prg","prn","ps1","ps1xml","ps2","ps2xml","psc1","psc2","psd1",
                "psm1","pvd","pwc","py","pyc","pyo","qpx","rb","rbx","reg","rgs","rox","rpj","rpm","run",
                "sbs","scar","scf","scpt","scptd","scr","script","sct","seed","sh","shb","shd","shs","spr",
                "sys","tcsh","tgz","thm","tlb","tms","u3p","udf","url","vb","vba","vbe","vbs","vbscript",
                "vdl","vdo","vxd","wcm","widget","wmf","workflow","wpk","ws","wsc","wsf","wsh","wst","xap",
                "xhtml","xpi","xqt","zlq","zsh"
            }
            
            if file_ext in REJECTED_EXTS:
                print(f"DEBUG: File {file_path} has unsupported extension: {file_ext}")
                return True
                
            return False
        except (OSError, AttributeError) as e:
            print(f"DEBUG: Error checking file {file_path}: {e}")
            return True

    async def _upload_file(self, file_path: Path) -> Optional[str]:
        """Upload file to Bytescale and return file path."""
        if not self.session:
            return None

        try:
            # Use the correct API endpoint for uploads
            url = f"{self.api_base_url}/v2/accounts/{self.account_id}/uploads/binary"
            
            # Read file data
            file_data = file_path.read_bytes()
            
            # Headers with authorization
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "text/plain"
            }
            
            # Parameters with filename
            params = {
                "fileName": file_path.name
            }
            
            async with self.session.post(url, data=file_data, headers=headers, params=params) as response:
                if response.status == 200:
                    try:
                        file_info = await response.json()
                        uploaded_path = file_info.get("filePath")
                        return uploaded_path
                    except:
                        # Response might not be JSON, try to get text
                        response_text = await response.text()
                        return response_text
                else:
                    print(f"Bytescale upload failed: {response.status} - {await response.text()}")
                    return None

        except Exception as e:
            print(f"Bytescale upload error: {str(e)}")
            return None

    async def _scan_file(self, uploaded_path: str) -> Optional[dict]:
        """Scan uploaded file using Bytescale antivirus."""
        if not self.session:
            return None

        try:
            # Use CDN endpoint for antivirus scanning
            scan_url = f"{self.cdn_base_url}/{self.account_id}/antivirus{uploaded_path}"
            
            # Add authorization and JSON response parameters
            params = {
                "apiKey": self.api_key,
                "json": "true"
            }
            
            async with self.session.get(scan_url, params=params) as response:
                if response.status == 200:
                    try:
                        job_info = await response.json()
                        
                        # Check if scan completed immediately
                        status = job_info.get("status")
                        if status == "Succeeded":
                            return job_info
                        elif status in ["Failed", "Cancelled"]:
                            print(f"Bytescale scan failed: {status} - {job_info.get('error', 'Unknown error')}")
                            return None
                        
                        # If still pending, get job URL for polling
                        job_url = job_info.get("jobUrl") or job_info.get("href")
                        if job_url:
                            # Poll for results
                            return await self._poll_scan_results(job_url)
                        
                        return None
                    except:
                        print(f"Bytescale scan response parsing failed")
                        return None
                else:
                    print(f"Bytescale scan failed: {response.status} - {await response.text()}")
                    return None

        except Exception as e:
            print(f"Bytescale scan error: {str(e)}")
            return None

    async def _poll_scan_results(self, job_url: str) -> Optional[dict]:
        """Poll for scan results."""
        try:
            max_attempts = 10  # 20 seconds max
            attempts = 0
            
            while attempts < max_attempts:
                headers = {
                    "Authorization": f"Bearer {self.api_key}"
                }
                
                async with self.session.get(job_url, headers=headers) as response:
                    if response.status == 200:
                        job_data = await response.json()
                        status = job_data.get("status")
                        
                        if status == "Succeeded":
                            return job_data
                        elif status in ["Failed", "Cancelled"]:
                            print(f"Bytescale scan failed: {status} - {job_data.get('error', 'Unknown error')}")
                            return None
                        
                        # Wait before retrying
                        await asyncio.sleep(2)
                        attempts += 1
                    else:
                        print(f"Bytescale poll failed: {response.status}")
                        return None
            
            print("Bytescale scan polling timeout")
            return None

        except Exception as e:
            print(f"Bytescale polling error: {str(e)}")
            return None

    async def scan(self, file_path: Path) -> ScanResult:
        """
        Scan a file using Bytescale API.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            ScanResult: The result of the scan
        """
        if not self.initialized:
            await self.initialize()

        # Check if Bytescale is enabled
        if not settings.BYTESCALE_ENABLED:
            return ScanResult(
                safe=True,
                threats=[],
                scan_time=datetime.utcnow(),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=0.0,
                error="Bytescale scanning is disabled",
                details={"skipped": True, "reason": "disabled"}
            )

        try:
            # Check if file should be skipped
            if self._should_skip_file(file_path):
                return ScanResult(
                    safe=True,
                    threats=[],
                    scan_time=datetime.utcnow(),
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine=self.name,
                    confidence=0.0,
                    error="File too large for Bytescale analysis (>500MB)",
                    details={"skipped": True, "reason": "file_too_large"}
                )

            # Upload file to Bytescale
            uploaded_path = await self._upload_file(file_path)
            if not uploaded_path:
                return ScanResult(
                    safe=True,
                    threats=[],
                    scan_time=datetime.utcnow(),
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine=self.name,
                    confidence=0.0,
                    error="Failed to upload file to Bytescale",
                    details={"skipped": True, "reason": "upload_failed"}
                )

            # Scan file
            scan_result = await self._scan_file(uploaded_path)
            if not scan_result:
                return ScanResult(
                    safe=True,
                    threats=[],
                    scan_time=datetime.utcnow(),
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine=self.name,
                    confidence=0.0,
                    error="Failed to scan file with Bytescale",
                    details={"skipped": True, "reason": "scan_failed"}
                )

            # Parse scan results
            is_safe = True
            threats = []
            confidence = 0.0
            details = {"bytescale_analysis": scan_result}

            # Debug logging
            print(f"DEBUG: Bytescale scan result: {scan_result}")
            print(f"DEBUG: Scan result type: {type(scan_result)}")

            # Parse Bytescale response structure
            # The response contains files array with virus detection results
            # Files are nested under summary.result.files
            summary = scan_result.get("summary", {})
            result_data = summary.get("result", {})
            files = result_data.get("files", [])
            print(f"DEBUG: Files array: {files}")
            
            if files:
                # Check each file for viruses
                for file_info in files:
                    viruses = file_info.get("viruses", [])
                    status = file_info.get("status", "Unknown")
                    
                    print(f"DEBUG: File info - viruses: {viruses}, status: {status}")
                    print(f"DEBUG: is_safe before check: {is_safe}")
                    
                    if viruses and len(viruses) > 0:
                        # Viruses detected
                        is_safe = False
                        threats.append(f"Bytescale detected viruses: {', '.join(viruses)}")
                        confidence = 0.95
                        details["malware_detected"] = True
                        details["malware_type"] = "virus"
                        details["viruses"] = viruses
                        print(f"DEBUG: Viruses detected, is_safe set to: {is_safe}")
                        break
                    elif status == "Healthy":
                        # File is healthy
                        is_safe = True  # Explicitly set to True
                        confidence = 0.9
                        details["analysis_result"] = "safe"
                        details["file_status"] = status
                        print(f"DEBUG: Status Healthy, is_safe set to: {is_safe}")
                    elif status == "Infected":
                        # File is infected
                        is_safe = False
                        threats.append(f"Bytescale detected infected file: {status}")
                        confidence = 0.9
                        details["malware_detected"] = True
                        details["malware_type"] = "infected"
                        print(f"DEBUG: Status Infected, is_safe set to: {is_safe}")
                        break
                    else:
                        # Unknown status, treat as potentially unsafe
                        is_safe = False
                        threats.append(f"Bytescale unknown status: {status}")
                        confidence = 0.7
                        details["malware_detected"] = True
                        details["malware_type"] = "unknown_status"
                        print(f"DEBUG: Unknown status, is_safe set to: {is_safe}")
                        break
            else:
                # No files array, check for summary result
                summary = scan_result.get("summary", {})
                result = summary.get("result", "clean")
                
                if result != "clean":
                    is_safe = False
                    threats.append(f"Bytescale detected: {result}")
                    confidence = 0.9
                    details["malware_detected"] = True
                    details["malware_type"] = result
                else:
                    confidence = 0.85
                    details["analysis_result"] = "safe"
            
            print(f"DEBUG: Final is_safe value: {is_safe}")
            print(f"DEBUG: Final threats: {threats}")
            
            # Convert to human-readable threats
            human_threats = self._get_human_readable_threats(threats, details)
            details['original_threats'] = threats  # Keep original for debugging
            print(f"DEBUG: Human-readable threats: {human_threats}")

            return ScanResult(
                safe=is_safe,
                threats=human_threats,
                scan_time=datetime.utcnow(),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=confidence,
                error=None,
                details=details
            )

        except Exception as e:
            return ScanResult(
                safe=True,  # Fail open on errors
                threats=[],
                scan_time=datetime.utcnow(),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=0.0,
                error=f"Bytescale scan error: {str(e)}",
                details={"skipped": True, "reason": "scan_error"}
            )

    def _get_human_readable_threats(self, threats: list, details: dict) -> list:
        """Convert Bytescale technical threat descriptions to human-readable keywords."""
        human_threats = []
        
        for threat in threats:
            threat_lower = threat.lower()
            
            if 'virus' in threat_lower:
                human_threats.append('Virus')
            elif 'infected' in threat_lower:
                human_threats.append('Infected')
            elif 'malware' in threat_lower:
                human_threats.append('Malware')
            elif 'unknown' in threat_lower:
                human_threats.append('Suspicious')
            else:
                # Extract the main threat type from the description
                if 'detected' in threat_lower:
                    # Extract what was detected
                    if ':' in threat:
                        detected_part = threat.split(':', 1)[1].strip()
                        if detected_part:
                            human_threats.append(detected_part.split()[0].title())
                    else:
                        human_threats.append('Threat')
                else:
                    human_threats.append('Suspicious')
        
        # Remove duplicates and return
        return list(set(human_threats)) if human_threats else []
