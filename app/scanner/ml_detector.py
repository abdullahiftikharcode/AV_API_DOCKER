import numpy as np
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple, Dict
import math
import re
import sys
from cachetools import TTLCache, cached

from .base import BaseScanner, ScanResult
from ..config import settings
from ..utils.memory_manager import memory_manager


class MLDetector(BaseScanner):
    """Machine Learning-based malware detection using statistical analysis (EMBER functionality removed)."""

    def __init__(self):
        super().__init__("ML Detector")
        self.version = "2.0"
        self.description = "Statistical analysis-based detection (EMBER removed)"
        
        # Models are disabled - EMBER functionality removed
        self.models = {}
        
        print("INFO: MLDetector initialized without EMBER models")

    async def initialize(self) -> None:
        """Initialize the scanner (no-op for entropy-based detection)."""
        self.initialized = True
        print("DEBUG: MLDetector initialized (entropy-based mode)")

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if len(data) == 0:
            return 0.0
            
        # Count frequency of each byte
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in frequency.values():
            p = float(count) / data_len
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy

    def _should_skip_entropy_analysis(self, file_path: Path) -> bool:
        """Check if file type should skip entropy analysis."""
        file_extension = file_path.suffix.lower()
        
        # Extensions that should NOT use entropy analysis
        skip_extensions = {
            # Android / Java
            '.apk', '.dex', '.jar',
            
            # Documents
            '.doc', '.docx', '.pdf', '.xls', '.xlsx', '.ppt', '.pptx', '.rtf',
            
            # Scripts / Macros
            '.js', '.vbs', '.bat', '.ps1', '.sh',
            
            # Compressed archives
            '.zip', '.rar', '.7z', '.tar', '.gz',
            
            # Media files
            '.jpg', '.jpeg', '.png', '.gif', '.mp3', '.mp4', '.avi', '.mov',
            
            # Linux binaries
            '.elf', '.so',
            
            # Others
            '.bin'  # unless confirmed it's a PE file
        }
        
        return file_extension in skip_extensions

    def _analyze_file(self, file_path: Path) -> Tuple[bool, float, List[str]]:
        """Analyze file using entropy-based detection (no ML models)."""
        try:
            # Skip entropy analysis for unsuitable file types
            if self._should_skip_entropy_analysis(file_path):
                print(f"DEBUG: Skipping entropy analysis for {file_path.name} (unsuitable file type)")
                return False, 0.0, []
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if len(data) == 0:
                return False, 0.0, []
            
            # Calculate file entropy
            entropy = self._calculate_entropy(data)
            
            # Simple heuristic: very high entropy might indicate packed/encrypted content
            # This is a basic fallback since EMBER models are removed
            if entropy > 7.5:  # High entropy threshold
                confidence = min(0.8, (entropy - 7.0) / 1.0)  # Scale to 0-0.8
                threats = ["High entropy content (possibly packed/encrypted)"]
                return True, confidence, threats
            
            # File appears normal based on entropy
            return False, 0.0, []
            
        except Exception as e:
            print(f"Error in ML analysis: {e}")
            return False, 0.0, []

    async def scan(self, file_path: Path) -> ScanResult:
        """Scan file using entropy analysis (EMBER removed)."""
        start_time = datetime.now()
        
        try:
            print(f"DEBUG: ML detector analyzing {file_path}")
            
            # Use entropy-based analysis instead of ML models
            is_threat, confidence, threats = self._analyze_file(file_path)
            
            scan_time = datetime.now()
            duration_ms = int((scan_time - start_time).total_seconds() * 1000)
            
            print(f"DEBUG: ML detector result - threat: {is_threat}, confidence: {confidence:.3f}")

            return ScanResult(
                safe=not is_threat,
                threats=threats,
                scan_time=scan_time,
                file_size=file_path.stat().st_size if file_path.exists() else 0,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=confidence
            )

        except Exception as e:
            scan_time = datetime.now()
            duration_ms = int((scan_time - start_time).total_seconds() * 1000)
            
            print(f"ERROR: ML detector failed: {e}")
            
            return ScanResult(
                safe=True,
                threats=[],
                scan_time=scan_time,
                file_size=file_path.stat().st_size if file_path.exists() else 0,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=0.0,
                error=str(e)
            )

    async def cleanup(self) -> None:
        """Cleanup resources."""
        self.models.clear()
        self.initialized = False 
        print("DEBUG: ML detector cleanup completed")