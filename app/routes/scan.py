from datetime import datetime
from fastapi import APIRouter, UploadFile, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List
import asyncio
import time

from ..scanner.container_manager import container_manager
from ..utils.memory_manager import memory_manager


router = APIRouter()


class ScanResponse(BaseModel):
    """API response model for scan results."""
    safe: bool
    threats: List[str]
    scanTime: datetime
    scanDurationMs: int  # Pure scanning time (excluding initialization overhead) in milliseconds
    containerDurationMs: int  # Total container time including all overhead in milliseconds
    fileSize: int
    fileName: str
    scanEngine: str


@router.post("/scan", response_model=ScanResponse)
async def scan_file(file: UploadFile, background_tasks: BackgroundTasks):
    """
    Scan a file for threats using multiple detection engines.
    Files are streamed directly to child containers without being stored in the main API container.
    Accepts any file type/extension.
    
    Args:
        file: The file to scan (any file type accepted)
        background_tasks: FastAPI background tasks
        
    Returns:
        ScanResponse: The scan results
        
    Raises:
        HTTPException: If scan fails or file is invalid
    """
    # Check if we can start a new scan
    if not await memory_manager.can_start_scan():
        raise HTTPException(
            status_code=429,
            detail="Maximum concurrent scans reached. Please try again later."
        )

    try:
        # Accept any file extension - no validation needed
        # Start timing the entire operation (including container overhead)
        total_start_time = time.time()
        
        # Stream file directly to child container for scanning
        result = await container_manager.scan_file_stream(file)
        
        # Calculate total operation duration
        total_duration_ms = int((time.time() - total_start_time) * 1000)

        if result.error:
            raise HTTPException(
                status_code=500,
                detail=f"Scan failed: {result.error}"
            )

        # Use the timing information from the container result
        # scanDurationMs = pure scanning time (excluding initialization overhead)
        # containerDurationMs = total container time (including all overhead)
        return ScanResponse(
            safe=result.safe,
            threats=result.threats,
            scanTime=result.scan_time,
            scanDurationMs=result.scan_duration_ms,  # Pure scanning time (excluding initialization)
            containerDurationMs=result.container_duration_ms,  # Total container time including all overhead
            fileSize=result.file_size,
            fileName=result.file_name,
            scanEngine=result.scan_engine
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Internal server error: {str(e)}"
        )
    finally:
        # Always decrement scan count
        await memory_manager.end_scan() 