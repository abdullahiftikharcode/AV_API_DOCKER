from datetime import datetime
from fastapi import APIRouter, UploadFile, HTTPException, BackgroundTasks
from pydantic import BaseModel
from typing import List
import asyncio
import time

from ..scanner.container_manager import container_manager
from ..utils.memory_manager import memory_manager


router = APIRouter()


class PythonExecutionRequest(BaseModel):
    """Request model for Python code execution."""
    code: str
    timeout: int = 300


class PythonExecutionResponse(BaseModel):
    """Response model for Python code execution."""
    safe: bool
    threats: List[str]
    scanTime: datetime
    scanDurationMs: int
    containerDurationMs: int
    fileSize: int
    fileName: str
    scanEngine: str
    details: dict = {}


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


@router.post("/execute-python", response_model=PythonExecutionResponse)
async def execute_python_code(request: PythonExecutionRequest, background_tasks: BackgroundTasks):
    """
    Execute Python code in a secure container without storing the source code.
    The code is piped into the container, executed, and then immediately deleted.
    
    Args:
        request: PythonExecutionRequest containing the code and timeout
        background_tasks: FastAPI background tasks
        
    Returns:
        PythonExecutionResponse: The execution results and threat analysis
        
    Raises:
        HTTPException: If execution fails or code is invalid
    """
    # Check if we can start a new scan
    if not await memory_manager.can_start_scan():
        raise HTTPException(
            status_code=429,
            detail="Maximum concurrent scans reached. Please try again later."
        )

    try:
        # Validate code length
        if len(request.code) > 1000000:  # 1MB limit
            raise HTTPException(
                status_code=400,
                detail="Code too long. Maximum 1MB allowed."
            )
        
        # Check for obviously malicious patterns
        dangerous_patterns = [
            'import os', 'import subprocess', 'import sys', 
            'eval(', 'exec(', '__import__', 'open(', 'file(',
            'subprocess.call', 'subprocess.Popen', 'os.system'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in request.code:
                return PythonExecutionResponse(
                    safe=False,
                    threats=[f"Potentially dangerous pattern detected: {pattern}"],
                    scanTime=datetime.utcnow(),
                    scanDurationMs=0,
                    containerDurationMs=0,
                    fileSize=len(request.code.encode()),
                    fileName='python_script.py',
                    scanEngine="container_ensemble"
                )
        
        # Execute Python code in container
        result = await container_manager.execute_python_code(request.code, request.timeout)
        
        if result.error:
            raise HTTPException(
                status_code=500,
                detail=f"Python execution failed: {result.error}"
            )

        return PythonExecutionResponse(
            safe=result.safe,
            threats=result.threats,
            scanTime=result.scan_time,
            scanDurationMs=result.scan_duration_ms,
            containerDurationMs=result.container_duration_ms,
            fileSize=result.file_size,
            fileName=result.file_name,
            scanEngine=result.scan_engine,
            details=result.details if hasattr(result, 'details') else {}
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