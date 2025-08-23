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

    def _get_human_readable_threats(self, entropy: float, file_path: Path) -> List[str]:
        """Convert technical analysis to human-readable threat descriptions."""
        threats = []
        
        # High entropy indicates obfuscated or encrypted content
        if entropy > 7.5:
            threats.append("Obfuscated")
        
        # Very high entropy suggests encryption or packing
        if entropy > 7.8:
            threats.append("Encrypted")
        
        # Check file extension for additional context
        file_extension = file_path.suffix.lower()
        
        # Add context-specific threats
        if file_extension in ['.exe', '.dll', '.sys']:
            if entropy > 7.5:
                threats.append("Suspicious Executable")
        elif file_extension in ['.js', '.vbs', '.ps1']:
            if entropy > 7.0:
                threats.append("Suspicious Script")
        elif file_extension in ['.doc', '.docx', '.pdf']:
            if entropy > 7.2:
                threats.append("Suspicious Document")
        
        # If no specific threats found but entropy is concerning
        if not threats and entropy > 7.0:
            threats.append("Unusual Content")
        
        return threats

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
            print(f"DEBUG: File entropy: {entropy:.3f}")
            
            # Get human-readable threats
            threats = self._get_human_readable_threats(entropy, file_path)
            
            # Determine if file is suspicious based on entropy
            is_threat = len(threats) > 0
            
            # Calculate confidence based on entropy level
            if is_threat:
                if entropy > 7.8:
                    confidence = 0.9  # Very high confidence for encrypted content
                elif entropy > 7.5:
                    confidence = 0.7  # High confidence for obfuscated content
                elif entropy > 7.0:
                    confidence = 0.5  # Medium confidence for unusual content
                else:
                    confidence = 0.3  # Low confidence
            else:
                confidence = 0.0
            
            print(f"DEBUG: Analysis result - threat: {is_threat}, confidence: {confidence:.3f}, threats: {threats}")
            
            return is_threat, confidence, threats
            
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