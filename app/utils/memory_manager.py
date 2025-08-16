import psutil
import asyncio
from typing import Optional
from dataclasses import dataclass
from ..config import settings

@dataclass
class MemoryStats:
    """Memory usage statistics."""
    total_mb: float
    used_mb: float
    available_mb: float
    percent: float


class MemoryManager:
    """Memory usage monitoring and management."""

    def __init__(self):
        self._active_scans = 0
        self._lock = asyncio.Lock()
        self._memory_warning_threshold = 0.85  # 85% of memory limit
        self._last_gc_trigger = 0  # Last time GC was triggered

    async def get_memory_stats(self) -> MemoryStats:
        """Get current memory usage statistics."""
        mem = psutil.virtual_memory()
        return MemoryStats(
            total_mb=mem.total / (1024 * 1024),
            used_mb=mem.used / (1024 * 1024),
            available_mb=mem.available / (1024 * 1024),
            percent=mem.percent
        )

    async def check_memory_pressure(self) -> Optional[str]:
        """
        Check if system is under memory pressure.
        
        Returns:
            Optional[str]: Warning message if under pressure, None otherwise
        """
        stats = await self.get_memory_stats()
        
        if stats.used_mb > settings.MEMORY_LIMIT_MB * self._memory_warning_threshold:
            return (
                f"High memory usage detected: {stats.used_mb:.1f}MB / "
                f"{settings.MEMORY_LIMIT_MB}MB ({stats.percent:.1f}%)"
            )
        return None

    async def can_start_scan(self) -> bool:
        """Check if a new scan can be started based on memory and concurrency limits."""
        async with self._lock:
            import structlog
            logger = structlog.get_logger()
            
            logger.info(
                "scan_concurrency_check",
                active_scans=self._active_scans,
                max_concurrent=settings.MAX_CONCURRENT_SCANS
            )
            
            if self._active_scans >= settings.MAX_CONCURRENT_SCANS:
                logger.warning(
                    "max_concurrent_scans_reached",
                    active_scans=self._active_scans,
                    max_concurrent=settings.MAX_CONCURRENT_SCANS
                )
                return False
            
            stats = await self.get_memory_stats()
            if stats.used_mb > settings.MEMORY_LIMIT_MB:
                logger.warning(
                    "memory_limit_exceeded",
                    used_mb=stats.used_mb,
                    limit_mb=settings.MEMORY_LIMIT_MB
                )
                return False
            
            self._active_scans += 1
            logger.info(
                "scan_started",
                active_scans=self._active_scans,
                max_concurrent=settings.MAX_CONCURRENT_SCANS
            )
            return True

    async def end_scan(self) -> None:
        """Mark a scan as completed."""
        async with self._lock:
            import structlog
            logger = structlog.get_logger()
            
            old_count = self._active_scans
            self._active_scans = max(0, self._active_scans - 1)
            
            logger.info(
                "scan_ended",
                old_active_scans=old_count,
                new_active_scans=self._active_scans
            )

    async def get_active_scans(self) -> int:
        """Get number of currently active scans."""
        async with self._lock:
            return self._active_scans

    @staticmethod
    def get_process_memory_info() -> dict:
        """Get detailed memory info for current process."""
        process = psutil.Process()
        mem_info = process.memory_info()
        return {
            'rss_mb': mem_info.rss / (1024 * 1024),  # Resident Set Size
            'vms_mb': mem_info.vms / (1024 * 1024),  # Virtual Memory Size
            'shared_mb': getattr(mem_info, 'shared', 0) / (1024 * 1024),  # Shared Memory
            'data_mb': getattr(mem_info, 'data', 0) / (1024 * 1024),  # Data Segment
        }

# Global memory manager instance
memory_manager = MemoryManager() 