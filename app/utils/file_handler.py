import os
import uuid
import mmap
import magic
import hashlib
import aiofiles
from pathlib import Path
from typing import AsyncGenerator, Tuple
from fastapi import UploadFile, HTTPException
from ..config import settings

class FileHandler:
    """Memory-efficient file handling utilities."""

    @staticmethod
    def validate_file_extension(filename: str) -> bool:
        """Check if file extension is in allowlist."""
        return any(filename.lower().endswith(ext) for ext in settings.ALLOWED_EXTENSIONS)

    @staticmethod
    async def get_mime_type(file_path: Path) -> str:
        """Get MIME type of file using python-magic."""
        return magic.from_file(str(file_path), mime=True)

    @staticmethod
    async def calculate_file_hash(file_path: Path) -> str:
        """Calculate SHA256 hash of file using memory mapping."""
        hash_sha256 = hashlib.sha256()
        
        try:
            with open(file_path, 'rb') as f:
                with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                    # Read in chunks to handle large files
                    for chunk in iter(lambda: mm.read(8192), b''):
                        hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except ValueError:  # File is empty
            return hash_sha256.hexdigest()

    @staticmethod
    async def save_upload_file(upload_file: UploadFile) -> Tuple[Path, int]:
        """
        Save uploaded file to temporary directory with memory-efficient streaming.
        
        Returns:
            Tuple[Path, int]: (file path, file size)
        """
        if not FileHandler.validate_file_extension(upload_file.filename):
            raise HTTPException(
                status_code=400,
                detail=f"File type not allowed. Allowed types: {', '.join(settings.ALLOWED_EXTENSIONS)}"
            )

        # Generate unique filename
        temp_filename = f"{uuid.uuid4()}{Path(upload_file.filename).suffix}"
        temp_path = Path(settings.TEMP_DIR) / temp_filename

        file_size = 0
        chunk_size = 8192  # 8KB chunks

        try:
            async with aiofiles.open(temp_path, 'wb') as f:
                while chunk := await upload_file.read(chunk_size):
                    file_size += len(chunk)
                    if file_size > settings.MAX_FILE_SIZE_MB * 1024 * 1024:
                        await FileHandler.cleanup_file(temp_path)
                        raise HTTPException(
                            status_code=413,
                            detail=f"File too large. Maximum size is {settings.MAX_FILE_SIZE_MB}MB"
                        )
                    await f.write(chunk)

            return temp_path, file_size
        except Exception as e:
            await FileHandler.cleanup_file(temp_path)
            raise HTTPException(status_code=500, detail=str(e))

    @staticmethod
    async def read_file_chunks(file_path: Path, chunk_size: int = 8192) -> AsyncGenerator[bytes, None]:
        """Memory-efficient file reading generator."""
        async with aiofiles.open(file_path, 'rb') as f:
            while chunk := await f.read(chunk_size):
                yield chunk

    @staticmethod
    async def cleanup_file(file_path: Path) -> None:
        """Safely delete temporary file."""
        try:
            if file_path.exists():
                os.remove(file_path)
        except Exception:
            pass  # Best effort cleanup 