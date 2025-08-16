import asyncio
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
from cachetools import TTLCache

from .base import BaseScanner, ScanResult
from .bytescale_scanner import BytescaleScanner
from .clamav import ClamAVScanner
from .yara_scanner import YARAScanner
from .ml_detector import MLDetector
from .malwarebazaar_scanner import MalwareBazaarScanner
from ..config import settings
from ..utils.memory_manager import memory_manager
from ..utils.file_handler import FileHandler


class EnsembleScanner(BaseScanner):
    """Coordinates multiple virus scanning engines."""

    def __init__(self):
        super().__init__("ensemble")
        self.scanners: List[BaseScanner] = []
        self._result_cache = TTLCache(
            maxsize=1000,
            ttl=settings.CACHE_TTL_HOURS * 3600
        )

    async def initialize(self) -> None:
        """Initialize all scanning engines."""
        try:
            # Initialize individual scanners (ordered by speed and priority)
            self.scanners = [
                BytescaleScanner(),        # Fast cloud-based analysis (first priority)
                ClamAVScanner(),           # Base detection (~45% weight)
                YARAScanner(),             # Pattern matching (~25% weight)
                MLDetector(),              # ML-based detection (~15% weight)
                MalwareBazaarScanner(),    # Fast threat intelligence (~15% weight)
            ]
            
            # Initialize all scanners in parallel
            await asyncio.gather(
                *[scanner.initialize() for scanner in self.scanners]
            )
            
            self.initialized = True
        except Exception as e:
            raise Exception(f"Failed to initialize ensemble scanner: {str(e)}")

    def _get_cached_result(self, file_hash: str) -> Optional[ScanResult]:
        """Get cached scan result if available."""
        if settings.ENABLE_RESULT_CACHING:
            return self._result_cache.get(file_hash)
        return None

    def _cache_result(self, file_hash: str, result: ScanResult) -> None:
        """Cache scan result."""
        if settings.ENABLE_RESULT_CACHING:
            self._result_cache[file_hash] = result

    def _combine_results(self, results: List[ScanResult]) -> ScanResult:
        """
        Combine results from multiple scanners using weighted voting.
        
        Weights:
        - ClamAV: 0.45 (base detection)
        - YARA: 0.25 (pattern matching)
        - ML: 0.15 (behavioral analysis)
        - MalwareBazaar: 0.15 (threat intelligence)
        """
        if not results:
            return ScanResult(
                safe=True,
                threats=[],
                scan_time=datetime.utcnow(),
                file_size=0,
                file_name="unknown",
                scan_engine=self.name,
                confidence=0.0,
                error="No scan results available"
            )

        # Initialize combined result
        combined_threats = []
        total_confidence = 0.0
        errors = []
        weights = {
            "bytescale": 0.0,        # Not used in ensemble (runs separately)
            "clamav": 0.45,
            "yara": 0.25,
            "ml_detector": 0.15,
            "malwarebazaar": 0.15,  # High weight for threat intelligence
        }

        # Combine results with weights
        for result in results:
            weight = weights.get(result.scan_engine, 0.1)
            
            # Add unique threats
            for threat in result.threats:
                if threat not in combined_threats:
                    combined_threats.append(threat)
            
            # Add weighted confidence
            total_confidence += result.confidence * weight
            
            # Collect errors
            if result.error:
                errors.append(f"{result.scan_engine}: {result.error}")

        # Normalize confidence
        total_weights = sum(
            weights.get(r.scan_engine, 0.1) 
            for r in results
        )
        if total_weights > 0:
            total_confidence = total_confidence / total_weights

        # Determine if file is safe based on threats and scanner results
        is_safe = True

        # If any scanner found threats or marked the file as unsafe, mark as unsafe
        if len(combined_threats) > 0 or any(not r.safe for r in results):
            is_safe = False

        return ScanResult(
            safe=is_safe,
            threats=combined_threats,
            scan_time=datetime.utcnow(),
            file_size=results[0].file_size,
            file_name=results[0].file_name,
            scan_engine=self.name,
            confidence=total_confidence,
            error="; ".join(errors) if errors else None
        )

    async def scan(self, file_path: Path) -> ScanResult:
        """
        Scan a file using all available engines.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            ScanResult: Combined scan results
        """
        if not self.initialized:
            await self.initialize()

        try:
            # Check memory pressure
            if warning := await memory_manager.check_memory_pressure():
                return ScanResult(
                    safe=True,
                    threats=[],
                    scan_time=datetime.utcnow(),
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine=self.name,
                    confidence=0.0,
                    error=f"Memory pressure: {warning}"
                )

            # Check scan cache
            file_hash = await FileHandler.calculate_file_hash(file_path)
            if cached_result := self._get_cached_result(file_hash):
                return cached_result

            # Run Bytescale scanner first (fast path for files under 500MB)
            try:
                print(f"DEBUG: Ensemble running {len(self.scanners)} scanners: {[s.name for s in self.scanners]}")
                
                # Start timing pure scanning (without container overhead)
                pure_scan_start = time.time()
                
                # First, try Bytescale scanner
                bytescale_scanner = self.scanners[0]  # Bytescale is first
                if not settings.BYTESCALE_ENABLED:
                    print(f"DEBUG: Bytescale is disabled, skipping to ensemble scanning")
                    bytescale_result = ScanResult(
                        safe=True,
                        threats=[],
                        scan_time=datetime.utcnow(),
                        file_size=file_path.stat().st_size,
                        file_name=file_path.name,
                        scan_engine=bytescale_scanner.name,
                        confidence=0.0,
                        error="Bytescale scanning is disabled",
                        details={"skipped": True, "reason": "disabled"}
                    )
                else:
                    bytescale_result = await bytescale_scanner.scan(file_path)
                
                # Check if Bytescale provided a definitive result
                if bytescale_result.details and not bytescale_result.details.get("skipped", False):
                    # Bytescale successfully analyzed the file
                    if not bytescale_result.safe:
                        # File is unsafe according to Bytescale - return immediately
                        print(f"DEBUG: Bytescale detected threat, returning early: {bytescale_result.threats}")
                        bytescale_result.scan_duration_ms = int((time.time() - pure_scan_start) * 1000)
                        return bytescale_result
                    else:
                        # File is safe according to Bytescale - return immediately
                        print(f"DEBUG: Bytescale confirmed file is safe, returning early")
                        bytescale_result.scan_duration_ms = int((time.time() - pure_scan_start) * 1000)
                        return bytescale_result
                
                # Bytescale was skipped or failed, continue with ensemble scanning
                print(f"DEBUG: Bytescale skipped/failed, continuing with ensemble scanning")
                
                # Run remaining scanners in parallel (excluding Bytescale)
                remaining_scanners = self.scanners[1:]
                tasks = [scanner.scan(file_path) for scanner in remaining_scanners]
                
                # Run tasks with timeout
                results = await asyncio.wait_for(
                    asyncio.gather(*tasks, return_exceptions=True),
                    timeout=settings.SCAN_TIMEOUT_SECONDS
                )
                
                # Calculate pure scanning time
                pure_scan_duration_ms = int((time.time() - pure_scan_start) * 1000)
                print(f"DEBUG: Pure scanning time (without container overhead): {pure_scan_duration_ms}ms")
                print(f"DEBUG: Ensemble got {len(results)} results from scanners")
                
                # Handle any exceptions from individual scanners
                valid_results = []
                for i, result in enumerate(results):
                    scanner_name = remaining_scanners[i].name
                    if isinstance(result, Exception):
                        print(f"ERROR: Scanner '{scanner_name}' failed with exception: {result}")
                        continue
                    print(f"DEBUG: Scanner '{scanner_name}' completed successfully")
                    valid_results.append(result)

                if not valid_results:
                    return ScanResult(
                        safe=True,
                        threats=[],
                        scan_time=datetime.utcnow(),
                        file_size=file_path.stat().st_size,
                        file_name=file_path.name,
                        scan_engine=self.name,
                        confidence=0.0,
                        error="All remaining scanners failed"
                    )

                # Combine results
                combined_result = self._combine_results(valid_results)
                
                # Store the pure scanning time in the result
                combined_result.scan_duration_ms = pure_scan_duration_ms
                
                # Cache result
                self._cache_result(file_hash, combined_result)
                
                return combined_result

            except asyncio.TimeoutError:
                return ScanResult(
                    safe=True,
                    threats=[],
                    scan_time=datetime.utcnow(),
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine=self.name,
                    confidence=0.0,
                    error=f"Scan timeout after {settings.SCAN_TIMEOUT_SECONDS} seconds"
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
        """Cleanup all scanner resources."""
        await asyncio.gather(
            *[scanner.cleanup() for scanner in self.scanners]
        )
        self.scanners = []
        self._result_cache.clear()
        self.initialized = False 