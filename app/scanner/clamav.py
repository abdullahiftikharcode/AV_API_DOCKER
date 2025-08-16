import clamd
from datetime import datetime
from pathlib import Path
from tenacity import retry, stop_after_attempt, wait_exponential

from .base import BaseScanner, ScanResult
from ..config import settings
from ..utils.memory_manager import memory_manager


class ClamAVScanner(BaseScanner):
    """ClamAV virus scanner implementation."""

    def __init__(self):
        super().__init__("clamav")
        self.clamd = None

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10)
    )
    async def initialize(self) -> None:
        """Initialize ClamAV connection with retry logic."""
        try:
            self.clamd = clamd.ClamdUnixSocket(path="/tmp/clamav/run/clamd.sock")
            # Test connection
            self.clamd.ping()
            self.initialized = True
        except Exception as e:
            raise Exception(f"Failed to initialize ClamAV: {str(e)}")

    async def scan(self, file_path: Path) -> ScanResult:
        """
        Scan a file using ClamAV.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            ScanResult: The scan results
        """
        if not self.initialized:
            await self.initialize()

        try:
            # Check memory pressure before scanning
            if warning := await memory_manager.check_memory_pressure():
                return ScanResult(
                    safe=True,  # Fail open on resource constraints
                    threats=[],
                    scan_time=datetime.utcnow(),
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine=self.name,
                    confidence=0.0,
                    error=f"Memory pressure: {warning}"
                )

            # Perform scan
            with open(file_path, 'rb') as f:
                scan_result = self.clamd.instream(f)
            
            # Parse results
            threats = []
            is_clean = True
            
            if scan_result:
                result_type, result_msg = scan_result['stream']
                is_clean = result_type == 'OK'
                if not is_clean:
                    if isinstance(result_msg, str):
                        threats.append(result_msg)
                    elif isinstance(result_msg, list):
                        threats.extend(result_msg)
                    elif isinstance(result_msg, tuple):
                        threats.extend(list(result_msg))

            return ScanResult(
                safe=is_clean,
                threats=threats,
                scan_time=datetime.utcnow(),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=0.9 if threats else 0.6  # Higher confidence for positive detections
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
                error=str(e)
            )

    async def cleanup(self) -> None:
        """Cleanup ClamAV resources."""
        if self.clamd:
            try:
                self.clamd = None
            except Exception:
                pass  # Best effort cleanup
        self.initialized = False 