from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Any
from pathlib import Path


@dataclass
class ScanResult:
    """Represents the result of a single scan engine."""
    safe: bool
    threats: List[str]
    scan_time: datetime
    file_size: int
    file_name: str
    scan_engine: str
    confidence: float  # 0.0 to 1.0
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None  # Additional analysis details
    scan_duration_ms: Optional[int] = None  # Pure scanning time in milliseconds


class BaseScanner(ABC):
    """Abstract base class for all virus scanning engines."""
    
    def __init__(self, name: str):
        self.name = name
        self.initialized = False

    @abstractmethod
    async def initialize(self) -> None:
        """Initialize the scanner with necessary resources."""
        pass

    @abstractmethod
    async def scan(self, file_path: Path) -> ScanResult:
        """
        Scan a file for threats.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            ScanResult: The result of the scan
            
        Raises:
            Exception: If scan fails or timeout occurs
        """
        pass

    @abstractmethod
    async def cleanup(self) -> None:
        """Cleanup resources used by the scanner."""
        pass

    async def __aenter__(self):
        """Context manager entry."""
        if not self.initialized:
            await self.initialize()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        await self.cleanup() 