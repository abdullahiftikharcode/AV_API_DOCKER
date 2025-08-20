import subprocess
import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from .base import BaseScanner, ScanResult
from ..config import settings
from ..utils.memory_manager import memory_manager


class ClamAVScanner(BaseScanner):
    """ClamAV virus scanner implementation using direct clamscan command."""

    def __init__(self):
        super().__init__("clamav")
        self.clamscan_path = None

    async def initialize(self) -> None:
        """Initialize ClamAV scanner by verifying clamscan binary availability."""
        try:
            # Check if clamscan binary is available
            result = subprocess.run(['which', 'clamscan'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                self.clamscan_path = result.stdout.strip()
                print(f"DEBUG: ClamAV scanner initialized with clamscan at: {self.clamscan_path}")
            else:
                # Fallback to common paths
                common_paths = ['/usr/bin/clamscan', '/usr/local/bin/clamscan', 'clamscan']
                for path in common_paths:
                    try:
                        result = subprocess.run([path, '--version'], 
                                              capture_output=True, text=True, timeout=5)
                        if result.returncode == 0:
                            self.clamscan_path = path
                            print(f"DEBUG: ClamAV scanner initialized with clamscan at: {self.clamscan_path}")
                            break
                    except (subprocess.TimeoutExpired, FileNotFoundError):
                        continue
                
                if not self.clamscan_path:
                    raise Exception("clamscan binary not found in system PATH or common locations")
            
            self.initialized = True
            print("DEBUG: ClamAV scanner initialized successfully")
            
        except Exception as e:
            raise Exception(f"Failed to initialize ClamAV scanner: {str(e)}")

    async def scan(self, file_path: Path) -> ScanResult:
        """
        Scan a file using ClamAV clamscan command.
        
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

            # Perform scan using clamscan command
            cmd = [
                self.clamscan_path,
                '--no-summary',           # Don't show summary
                '--infected',              # Only show infected files
                '--suppress-ok-results',   # Don't show OK results
                '--database=/tmp/clamav/db',  # Use our virus databases
                str(file_path)
            ]
            
            # Run clamscan with timeout
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for large files
            )
            
            # Parse results
            threats = []
            is_clean = True
            
            if result.returncode == 0:
                # File is clean (no threats found)
                is_clean = True
            elif result.returncode == 1:
                # File is infected (threats found)
                is_clean = False
                # Parse threat information from stdout
                if result.stdout.strip():
                    threat_lines = result.stdout.strip().split('\n')
                    for line in threat_lines:
                        if line.strip() and ':' in line:
                            # Extract threat name from output like "file: ThreatName.UNOFFICIAL FOUND"
                            parts = line.split(':')
                            if len(parts) >= 2:
                                threat_name = parts[1].strip()
                                if 'FOUND' in threat_name:
                                    threat_name = threat_name.replace('FOUND', '').strip()
                                    threats.append(threat_name)
            else:
                # Error occurred
                error_msg = result.stderr.strip() if result.stderr else f"clamscan failed with return code {result.returncode}"
                print(f"WARNING: ClamAV scan error: {error_msg}")
                # Fail open - assume file is safe on error
                is_clean = True

            return ScanResult(
                safe=is_clean,
                threats=threats,
                scan_time=datetime.utcnow(),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=0.9 if threats else 0.6  # Higher confidence for positive detections
            )

        except subprocess.TimeoutExpired:
            return ScanResult(
                safe=True,  # Fail open on timeout
                threats=[],
                scan_time=datetime.utcnow(),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=0.0,
                error="ClamAV scan timed out after 5 minutes"
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
                error=f"ClamAV scan failed: {str(e)}"
            )

    async def cleanup(self) -> None:
        """Cleanup ClamAV resources."""
        self.clamscan_path = None
        self.initialized = False 