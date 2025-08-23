import asyncio
import time
from datetime import datetime, timezone
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
    """Coordinates multiple virus scanning engines with early termination on threat detection."""

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
                MLDetector(),              # Entropy-based mathematical analysis (~15% weight)
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

    def _create_safe_fallback_result(self, file_path: Path, error: str = None) -> ScanResult:
        """Create a safe fallback result."""
        return ScanResult(
            safe=True,
            threats=[],
            scan_time=datetime.now(timezone.utc),
            file_size=file_path.stat().st_size,
            file_name=file_path.name,
            scan_engine=self.name,
            confidence=0.0,
            error=error
        )

    async def _scan_with_early_termination(self, file_path: Path, scanners: List[BaseScanner]) -> ScanResult:
        """
        Run scanners and return immediately on first unsafe result.
        Returns safe result only if all scanners complete successfully as safe.
        """
        if not scanners:
            return self._create_safe_fallback_result(file_path, "No scanners available")

        # Create tasks for all scanners
        scanner_tasks = {}
        for scanner in scanners:
            task = asyncio.create_task(scanner.scan(file_path))
            scanner_tasks[task] = scanner.name

        completed_results = []
        
        try:
            # Process results as they complete
            while scanner_tasks:
                # Wait for first completion
                done, pending = await asyncio.wait(
                    scanner_tasks.keys(),
                    return_when=asyncio.FIRST_COMPLETED,
                    timeout=settings.SCAN_TIMEOUT_SECONDS
                )
                
                if not done:
                    # Timeout occurred
                    for task in pending:
                        task.cancel()
                    break
                
                # Process completed tasks
                for task in done:
                    scanner_name = scanner_tasks.pop(task)
                    
                    try:
                        result = await task
                        print(f"DEBUG: Scanner '{scanner_name}' completed with safe={result.safe}")
                        
                        # EARLY TERMINATION: If any scanner finds threats, return immediately
                        if not result.safe and result.threats:
                            print(f"DEBUG: THREAT DETECTED by '{scanner_name}': {result.threats}")
                            print(f"DEBUG: Terminating remaining {len(scanner_tasks)} scanner tasks")
                            
                            # Cancel all remaining tasks
                            for remaining_task in scanner_tasks.keys():
                                remaining_task.cancel()
                            
                            # Return the unsafe result immediately
                            return result
                        
                        # Scanner completed safely, add to completed results
                        completed_results.append(result)
                        
                    except Exception as e:
                        print(f"ERROR: Scanner '{scanner_name}' failed: {e}")
                        # Continue with other scanners on individual failures
                        
            # If we reach here, all scanners completed without finding threats
            # or timed out. Return a combined safe result.
            if completed_results:
                # All completed scanners were safe
                return self._combine_safe_results(completed_results, file_path)
            else:
                return self._create_safe_fallback_result(
                    file_path, 
                    "All scanners failed or timed out"
                )
                
        except Exception as e:
            # Cancel any remaining tasks
            for task in scanner_tasks.keys():
                task.cancel()
            return self._create_safe_fallback_result(file_path, f"Scan error: {str(e)}")

    def _combine_safe_results(self, results: List[ScanResult], file_path: Path) -> ScanResult:
        """
        Combine multiple safe results into a single safe result.
        This is only called when all scanners returned safe results.
        """
        if not results:
            return self._create_safe_fallback_result(file_path, "No results to combine")

        # Calculate average confidence from safe results
        total_confidence = sum(r.confidence for r in results)
        avg_confidence = total_confidence / len(results) if results else 0.0
        
        # Collect any errors
        errors = [r.error for r in results if r.error]

        return ScanResult(
            safe=True,
            threats=[],  # All results were safe, so no threats
            scan_time=datetime.now(timezone.utc),
            file_size=results[0].file_size,
            file_name=results[0].file_name,
            scan_engine=self.name,
            confidence=avg_confidence,
            error="; ".join(errors) if errors else None,
            details={
                "scanners_completed": len(results),
                "all_safe": True
            }
        )

    async def scan(self, file_path: Path) -> ScanResult:
        """
        Scan a file using all available engines with early termination.
        
        Returns immediately on first threat detection, otherwise waits for all
        scanners to complete and returns safe result.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            ScanResult: First unsafe result or combined safe result
        """
        if not self.initialized:
            await self.initialize()

        try:
            # Check memory pressure
            if warning := await memory_manager.check_memory_pressure():
                return self._create_safe_fallback_result(
                    file_path, 
                    f"Memory pressure: {warning}"
                )

            # Check scan cache
            file_hash = await FileHandler.calculate_file_hash(file_path)
            if cached_result := self._get_cached_result(file_hash):
                return cached_result

            # Start timing
            pure_scan_start = time.time()
            print(f"DEBUG: Starting ensemble scan with {len(self.scanners)} scanners")
                
            # Try Bytescale first (fast path)
            bytescale_scanner = self.scanners[0]  # Bytescale is first
            remaining_scanners = self.scanners[1:]
            
            if settings.BYTESCALE_ENABLED:
                print("DEBUG: Running Bytescale scanner first")
                bytescale_result = await bytescale_scanner.scan(file_path)
                
                # Check if Bytescale provided a definitive result
                if bytescale_result.details and not bytescale_result.details.get("skipped", False):
                    if not bytescale_result.safe:
                        # THREAT FOUND: Return immediately
                        print(f"DEBUG: Bytescale detected threat, returning early: {bytescale_result.threats}")
                        bytescale_result.scan_duration_ms = int((time.time() - pure_scan_start) * 1000)
                        self._cache_result(file_hash, bytescale_result)
                        return bytescale_result
                    else:
                        # SAFE: Return immediately (Bytescale is authoritative)
                        print("DEBUG: Bytescale confirmed file is safe, returning early")
                        bytescale_result.scan_duration_ms = int((time.time() - pure_scan_start) * 1000)
                        self._cache_result(file_hash, bytescale_result)
                        return bytescale_result
                
            # Bytescale disabled/failed, run ensemble with early termination
            print(f"DEBUG: Running ensemble scan with {len(remaining_scanners)} remaining scanners")
            result = await self._scan_with_early_termination(file_path, remaining_scanners)
            
            # Set timing and cache result
            result.scan_duration_ms = int((time.time() - pure_scan_start) * 1000)
            print(f"DEBUG: Ensemble scan completed in {result.scan_duration_ms}ms")
            
            self._cache_result(file_hash, result)
            return result

        except Exception as e:
            print(f"ERROR: Ensemble scan failed: {e}")
            return self._create_safe_fallback_result(file_path, str(e))

    async def cleanup(self) -> None:
        """Cleanup all scanner resources."""
        await asyncio.gather(
            *[scanner.cleanup() for scanner in self.scanners],
            return_exceptions=True  # Don't fail if individual cleanups fail
        )
        self.scanners = []
        self._result_cache.clear()
        self.initialized = False