from fastapi import APIRouter
from pydantic import BaseModel
from typing import Dict, Optional

from ..utils.memory_manager import memory_manager


router = APIRouter()


class HealthResponse(BaseModel):
    """API response model for health check."""
    status: str
    memory: Dict[str, float]
    activeScanners: int
    memoryPressure: Optional[str]


@router.get("/health", response_model=HealthResponse)
async def health_check():
    """
    Check server health and resource usage.
    
    Returns:
        HealthResponse: Health check results
    """
    # Get memory stats
    mem_stats = await memory_manager.get_memory_stats()
    process_mem = memory_manager.get_process_memory_info()
    
    # Check memory pressure
    memory_pressure = await memory_manager.check_memory_pressure()
    
    # Get active scans
    active_scans = await memory_manager.get_active_scans()
    
    return HealthResponse(
        status="healthy" if not memory_pressure else "degraded",
        memory={
            "total_mb": mem_stats.total_mb,
            "used_mb": mem_stats.used_mb,
            "available_mb": mem_stats.available_mb,
            "usage_percent": mem_stats.percent,
            "process_rss_mb": process_mem["rss_mb"],
            "process_vms_mb": process_mem["vms_mb"]
        },
        activeScanners=active_scans,
        memoryPressure=memory_pressure
    ) 