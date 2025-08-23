import yara
import mmap
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List
from cachetools import TTLCache, cached

from .base import BaseScanner, ScanResult
from ..config import settings
from ..utils.memory_manager import memory_manager


class YARAScanner(BaseScanner):
    """YARA rules-based malware scanner."""

    def __init__(self):
        super().__init__("yara")
        self.rules = None
        self._rules_cache = TTLCache(maxsize=100, ttl=3600)  # 1 hour cache

    @cached(cache=TTLCache(maxsize=1, ttl=3600))  # Cache compiled rules for 1 hour
    def _compile_rules(self) -> yara.Rules:
        """Compile YARA rules from rule files."""
        rules_dict = {}
        rules_path = Path(settings.YARA_RULES_PATH)

        # Recursively find all .yar files
        for rule_file in rules_path.rglob("*.yar"):
            try:
                with open(rule_file) as f:
                    rules_dict[rule_file.stem] = f.read()
            except Exception as e:
                print(f"Error loading rule file {rule_file}: {e}")

        # Compile all rules together
        return yara.compile(sources=rules_dict)

    async def initialize(self) -> None:
        """Initialize YARA scanner with compiled rules."""
        try:
            self.rules = self._compile_rules()
            self.initialized = True
        except Exception as e:
            raise Exception(f"Failed to initialize YARA scanner: {str(e)}")

    def _get_rule_metadata(self, match) -> Dict[str, str]:
        """Extract metadata from YARA rule match."""
        metadata = {}
        if hasattr(match, 'meta'):
            metadata = match.meta
        return metadata

    def _get_match_description(self, match) -> str:
        """Get human-readable description of YARA match."""
        metadata = self._get_rule_metadata(match)
        if 'description' in metadata:
            return f"{match.rule}: {metadata['description']}"
        return match.rule

    async def scan(self, file_path: Path) -> ScanResult:
        """
        Scan a file using YARA rules.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            ScanResult: The scan results
        """
        if not self.initialized:
            await self.initialize()

        try:
            # Check memory pressure
            if warning := await memory_manager.check_memory_pressure():
                return ScanResult(
                    safe=True,
                    threats=[],
                    scan_time=datetime.now(timezone.utc),
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine=self.name,
                    confidence=0.0,
                    error=f"Memory pressure: {warning}"
                )

            threats: List[str] = []
            confidence = 0.6  # Base confidence

            # Use memory mapping for efficient file access
            with open(file_path, 'rb') as f:
                try:
                    # Try memory mapping first
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        matches = self.rules.match(data=mm)
                except ValueError:
                    # Fallback for small files that can't be memory mapped
                    matches = self.rules.match(data=f.read())

            # Process matches
            if matches:
                for match in matches:
                    threat_desc = self._get_match_description(match)
                    threats.append(threat_desc)
                    
                    # Adjust confidence based on metadata
                    metadata = self._get_rule_metadata(match)
                    if metadata.get('confidence'):
                        try:
                            rule_confidence = float(metadata['confidence'])
                            confidence = max(confidence, rule_confidence)
                        except (ValueError, TypeError):
                            pass

            return ScanResult(
                safe=len(threats) == 0,
                threats=threats,
                scan_time=datetime.now(timezone.utc),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=confidence if threats else 0.6
            )

        except Exception as e:
            return ScanResult(
                safe=True,  # Fail open on errors
                threats=[],
                scan_time=datetime.now(timezone.utc),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=0.0,
                error=str(e)
            )

    async def cleanup(self) -> None:
        """Cleanup YARA resources."""
        self.rules = None
        self._rules_cache.clear()
        self.initialized = False 