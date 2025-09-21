import asyncio
from .docker_client import DockerClient
import tempfile
import os
import time
import json
import structlog
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from app.config import settings
from fastapi import HTTPException

logger = structlog.get_logger()

@dataclass
class ContainerScanResult:
    """Result from container-based scan."""
    safe: bool
    threats: list
    scan_time: str
    scan_duration_ms: int  # Pure scanning time (excluding initialization overhead)
    container_duration_ms: int  # Total container time including all overhead
    file_size: int
    file_name: str
    scan_engine: str
    error: Optional[str] = None


class ContainerManager:
    """Manages per-request container creation and cleanup."""
    
    def __init__(self):
        self.docker_client = None
        self.container_image = "virus-scanner-scanner:latest"
        self.scan_timeout = settings.SCAN_TIMEOUT_SECONDS
        self.max_memory = "4g"  # Updated to 4GB for concurrent containers
        self.max_cpu = "1.0"    # Updated to 1 CPU core for concurrent containers
    
    def get_allowed_extensions(self) -> List[str]:
        """Get list of allowed file extensions from settings."""
        return settings.ALLOWED_EXTENSIONS
    
    def _get_docker_client(self):
        """Get Docker client, initializing if needed."""
        if self.docker_client is None:
            # Use Docker socket (mounted in container)
            try:
                # Create Docker client with Unix socket
                self.docker_client = DockerClient()
                if self.docker_client.ping():
                    logger.info("docker_client_initialized", base_url='unix:///var/run/docker.sock')
                    return self.docker_client
                else:
                    logger.error("docker_client_ping_failed")
                    self.docker_client = None
            except Exception as e:
                logger.error("docker_client_init_failed", error=str(e))
                self.docker_client = None
            
            # If all methods failed
            raise Exception("Failed to initialize Docker client with any connection method")
        return self.docker_client
        
    async def create_scan_container(self, file_path: Path, file_hash: str) -> Optional[str]:
        """Create a fresh container for scanning."""
        try:
            # Read the file content to pass to the child container
            with open(file_path, 'rb') as f:
                file_content = f.read()
            
            # Create a temporary file name for the scan
            scan_filename = file_path.name
            
            # Create container but don't start yet
            client = self._get_docker_client()
            
            # Use environment variables and file-based configuration instead of command-line arguments
            container_config = {
                'image': self.container_image,
                'command': ['/start.sh'],  # Just call the start script without arguments
                'volumes': {
                    str(Path(settings.YARA_RULES_PATH).parent): {'bind': '/app/rules', 'mode': 'ro'},
                    'virus-scanner-clamav': {'bind': '/var/lib/clamav', 'mode': 'ro'}  # Shared ClamAV virus definitions
                },
                'environment': {
                    'MAX_FILE_SIZE_MB': str(settings.MAX_FILE_SIZE_MB),
                    'SCAN_TIMEOUT_SECONDS': str(settings.SCAN_TIMEOUT_SECONDS),
                    'ML_ENABLE_PE_ANALYSIS': str(settings.ML_ENABLE_PE_ANALYSIS),
                    'ML_ENABLE_ENTROPY_ANALYSIS': str(settings.ML_ENABLE_ENTROPY_ANALYSIS),
                    # Primary method: Environment variables
                    'SCAN_FILE_PATH': f'/scan/{scan_filename}',
                    'SCAN_TIMEOUT': str(self.scan_timeout),
                    'SCAN_MODE': 'environment',
                    # Pass through HMAC configuration to child containers
                    'HMAC_SECRET_KEY': os.environ.get('HMAC_SECRET_KEY', ''),
                    'HMAC_ENABLED': str(settings.HMAC_ENABLED),
                    'HMAC_TIMESTAMP_TOLERANCE_SECONDS': str(settings.HMAC_TIMESTAMP_TOLERANCE_SECONDS),
                    # Pass through MalwareBazaar API configuration to child containers
                    'MALWAREBazaar_API_KEY': os.environ.get('MALWAREBazaar_API_KEY', ''),
                    'MALWAREBazaar_API_KEY_BACKUP': os.environ.get('MALWAREBazaar_API_KEY_BACKUP', ''),
                    'MALWAREBazaar_ENABLED': str(settings.MALWAREBazaar_ENABLED),
                    'MALWAREBazaar_TIMEOUT': str(settings.MALWAREBazaar_TIMEOUT),
                    # Pass through Bytescale API configuration to child containers
                    'BYTESCALE_API_KEY': os.environ.get('BYTESCALE_API_KEY', ''),
                    'BYTESCALE_ACCOUNT_ID': os.environ.get('BYTESCALE_ACCOUNT_ID', ''),
                    'BYTESCALE_ENABLED': str(settings.BYTESCALE_ENABLED),
                    'BYTESCALE_TIMEOUT': str(settings.BYTESCALE_TIMEOUT)
                },
                'mem_limit': self.max_memory,
                'cpu_period': 100000,
                'cpu_quota': int(float(self.max_cpu) * 100000),
                'network_disabled': False,  # Enable limited network access for MalwareBazaar API
                'read_only': False,  # Allow writes for ClamAV logs
                'tmpfs': {'/tmp': 'size=100m'},  # Temporary filesystem (reduced since ClamAV DBs are now shared)
                'detach': False,
                'AutoRemove': False, # Disable auto-removal to capture logs
            }
            
            # Log container creation (without sensitive config details)
            logger.info("creating_container", container_id="pending", image=self.container_image)
            
            container_id = client.create_container(container_config)
            if not container_id:
                logger.error("container_creation_failed")
                return None
            
            logger.info("container_created_successfully", container_id=container_id)
            
            # Start the container first before executing commands
            if not client.start_container(container_id):
                logger.error("container_start_failed", container_id=container_id)
                client.remove_container(container_id, force=True)
                return None
            
            logger.info("container_started", container_id=container_id)
            
            # Create the /scan directory in the container
            exec_result = client.exec_in_container(container_id, ['mkdir', '-p', '/scan'])
            if not exec_result or exec_result.get('ExitCode', 1) != 0:
                logger.error("failed_to_create_scan_dir", container_id=container_id)
                client.remove_container(container_id, force=True)
                return None
            
            # Copy file content to the container
            import tarfile
            import io
            
            # Create a tar archive with the file
            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                # Create tarinfo for the file
                tarinfo = tarfile.TarInfo(name=scan_filename)
                tarinfo.size = len(file_content)
                tarinfo.mode = 0o644
                
                # Add the file to the tar
                tar.addfile(tarinfo, io.BytesIO(file_content))
            
            # Copy the tar archive to the container
            tar_buffer.seek(0)
            if not client.put_archive(container_id, '/scan', tar_buffer.getvalue()):
                logger.error("failed_to_copy_file", container_id=container_id)
                client.remove_container(container_id, force=True)
                return None
            
            logger.info("file_copied_to_container", container_id=container_id, filename=scan_filename, file_size=len(file_content))
            
            # Create a configuration file with scan parameters
            config_content = f'''# Scan configuration file - created by container manager
SCAN_FILE_PATH={f'/scan/{scan_filename}'}
SCAN_TIMEOUT={self.scan_timeout}
SCAN_MODE=file
FILE_NAME={scan_filename}
FILE_SIZE={len(file_content)}
'''
            
            # Create config file in container
            config_tar = io.BytesIO()
            with tarfile.open(fileobj=config_tar, mode='w') as tar:
                # Create tarinfo for the config file
                tarinfo = tarfile.TarInfo(name='scan_config.env')
                tarinfo.size = len(config_content.encode())
                tarinfo.mode = 0o644
                
                # Add the config file to the tar
                tar.addfile(tarinfo, io.BytesIO(config_content.encode()))
            
            # Copy config file to container
            config_tar.seek(0)
            if not client.put_archive(container_id, '/', config_tar.getvalue()):
                logger.warning("failed_to_copy_config_file", container_id=container_id)
            
            logger.info("container_ready", container_id=container_id, file_hash=file_hash)
            
            return container_id
            
        except Exception as e:
            logger.error("container_creation_failed", error=str(e), file_hash=file_hash)
            return None

    async def create_streaming_container(self, filename: str) -> Optional[str]:
        """Create a fresh container for streaming file uploads."""
        try:
            # Create a temporary file name for the scan
            scan_filename = filename
            
            # Create container but don't start yet
            client = self._get_docker_client()
            
            # Use environment variables and file-based configuration instead of command-line arguments
            container_config = {
                'image': self.container_image,
                'command': ['python', '-c', 'import time; time.sleep(999999)'],  # Keep container running until we copy the file
                'volumes': {
                    str(Path(settings.YARA_RULES_PATH).parent): {'bind': '/app/rules', 'mode': 'ro'},
                    'virus-scanner-clamav': {'bind': '/var/lib/clamav', 'mode': 'ro'}  # Shared ClamAV virus definitions
                },
                'environment': {
                    'MAX_FILE_SIZE_MB': str(settings.MAX_FILE_SIZE_MB),
                    'SCAN_TIMEOUT_SECONDS': str(settings.SCAN_TIMEOUT_SECONDS),
                    'ML_ENABLE_PE_ANALYSIS': str(settings.ML_ENABLE_PE_ANALYSIS),
                    'ML_ENABLE_ENTROPY_ANALYSIS': str(settings.ML_ENABLE_ENTROPY_ANALYSIS),
                    # Primary method: Environment variables
                    'SCAN_FILE_PATH': f'/scan/{scan_filename}',
                    'SCAN_TIMEOUT': str(self.scan_timeout),
                    'SCAN_MODE': 'streaming',
                    # Pass through HMAC configuration to child containers
                    'HMAC_SECRET_KEY': os.environ.get('HMAC_SECRET_KEY', ''),
                    'HMAC_ENABLED': str(settings.HMAC_ENABLED),
                    'HMAC_TIMESTAMP_TOLERANCE_SECONDS': str(settings.HMAC_TIMESTAMP_TOLERANCE_SECONDS),
                    # Pass through MalwareBazaar API configuration to child containers
                    'MALWAREBazaar_API_KEY': os.environ.get('MALWAREBazaar_API_KEY', ''),
                    'MALWAREBazaar_API_KEY_BACKUP': os.environ.get('MALWAREBazaar_API_KEY_BACKUP', ''),
                    'MALWAREBazaar_ENABLED': str(settings.MALWAREBazaar_ENABLED),
                    'MALWAREBazaar_TIMEOUT': str(settings.MALWAREBazaar_TIMEOUT),
                    # Pass through Bytescale API configuration to child containers
                    'BYTESCALE_API_KEY': os.environ.get('BYTESCALE_API_KEY', ''),
                    'BYTESCALE_ACCOUNT_ID': os.environ.get('BYTESCALE_ACCOUNT_ID', ''),
                    'BYTESCALE_ENABLED': str(settings.BYTESCALE_ENABLED),
                    'BYTESCALE_TIMEOUT': str(settings.BYTESCALE_TIMEOUT)
                },
                'mem_limit': self.max_memory,
                'cpu_period': 100000,
                'cpu_quota': int(float(self.max_cpu) * 100000),
                'network_disabled': False,  # Enable limited network access for MalwareBazaar API
                'read_only': False,  # Allow writes for ClamAV logs
                'tmpfs': {'/tmp': 'size=100m'},  # Temporary filesystem (reduced since ClamAV DBs are now shared)
                'detach': False,
                'AutoRemove': False, # Disable auto-removal to capture logs
            }
            
            # Log streaming container creation (without sensitive config details)
            logger.info("creating_streaming_container", container_id="pending", image=self.container_image)
            
            container_id = client.create_container(container_config)
            if not container_id:
                logger.error("streaming_container_creation_failed")
                return None
            
            logger.info("streaming_container_created_successfully", container_id=container_id)
            
            # Start the container first before executing commands
            if not client.start_container(container_id):
                logger.error("streaming_container_start_failed", container_id=container_id)
                client.remove_container(container_id, force=True)
                return None
            
            logger.info("streaming_container_started", container_id=container_id)
            
            # Wait a moment and check if container is still running
            await asyncio.sleep(0.5)
            initial_status = client.get_container_status(container_id)
            logger.info("container_initial_status", container_id=container_id, status=initial_status)
            
            if initial_status != "running":
                logger.error("container_exited_immediately", container_id=container_id, status=initial_status)
                # Try to get container logs to see why it exited
                logs = client.get_container_logs(container_id)
                if logs:
                    logger.error("container_exit_logs", container_id=container_id, logs=logs[:500])
                client.remove_container(container_id, force=True)
                return None
            
            # The /scan directory is now created by the startup script
            # No need to execute mkdir command - the container handles this internally
            logger.info("streaming_container_ready", container_id=container_id, filename=scan_filename)
            
            return container_id
            
        except Exception as e:
            logger.error("streaming_container_creation_failed", error=str(e), filename=filename)
            return None
    
    async def cleanup_container(self, container_id: str) -> bool:
        """Clean up a container after log capture."""
        try:
            client = self._get_docker_client()
            
            # Check if container still exists before trying to remove it
            try:
                container_info = client._request('GET', f'/v1.41/containers/{container_id}/json')
                if container_info.status_code == 404:
                    # Container already removed, consider cleanup successful
                    logger.info("container_already_removed", container_id=container_id)
                    return True
            except Exception:
                # Container doesn't exist, consider cleanup successful
                logger.info("container_already_removed", container_id=container_id)
                return True
            
            # Remove the container
            response = client._request('DELETE', f'/v1.41/containers/{container_id}?force=true')
            if response.status_code == 204:
                logger.info("container_cleaned_up", container_id=container_id)
                return True
            else:
                logger.warning("container_cleanup_failed", container_id=container_id, status_code=response.status_code)
                return False
        except Exception as e:
            logger.error("container_cleanup_error", container_id=container_id, error=str(e))
            return False
    
    async def wait_for_container_completion(self, container_id: str, timeout: int) -> Dict[str, Any]:
        """Wait for container to complete and get results."""
        try:
            client = self._get_docker_client()
            
            # Wait for container to finish asynchronously
            result = await client.wait_container_async(container_id, timeout=timeout)
            if not result:
                logger.error("container_wait_failed", container_id=container_id)
                return {
                    'success': False,
                    'error': 'Container wait failed',
                    'logs': ''
                }
            
            # Get logs using streaming method to ensure capture on all platforms
            logs = await client.stream_container_logs_async(container_id, timeout=timeout) or ''
            
            # If streaming failed, fallback to regular method
            if not logs.strip():
                logger.warning("streaming_logs_failed_fallback", container_id=container_id)
            logs = await client.get_container_logs_async(container_id) or ''
            
            # If still no logs, try capturing during execution as final fallback
            if not logs.strip():
                logger.warning("regular_logs_failed_fallback", container_id=container_id)
                logs = await self.capture_container_logs_during_execution(container_id, timeout) or ''
            
            # Final fallback - try to get logs directly from Docker daemon
            if not logs.strip():
                logger.warning("all_log_methods_failed", container_id=container_id)
                try:
                    # Try to get logs with different parameters
                    logs = await client.get_container_logs_async(container_id, stdout=True, stderr=True) or ''
                    if not logs.strip():
                        # Try with different log format
                        import subprocess
                        subprocess_result = subprocess.run(
                            ['docker', 'logs', container_id], 
                            capture_output=True, 
                            text=True, 
                            timeout=10
                        )
                        if subprocess_result.returncode == 0:
                            logs = subprocess_result.stdout + subprocess_result.stderr
                        else:
                            logger.warning("docker_logs_subprocess_failed", container_id=container_id, returncode=subprocess_result.returncode, stderr=subprocess_result.stderr)
                except Exception as e:
                    logger.error("final_log_fallback_failed", container_id=container_id, error=str(e))
            
            # Log the final result of log capture attempts
            if logs.strip():
                logger.info("logs_captured_successfully", container_id=container_id, logs_length=len(logs), method="multi_fallback")
            else:
                logger.error("all_log_capture_methods_failed", container_id=container_id)
            
            # Log the final result
            logger.info("container_completed", 
                       container_id=container_id, 
                       exit_code=result.get('StatusCode', 1), 
                       logs_length=len(logs))
            
            # Log the actual logs for debugging
            logger.info("container_logs", logs=logs)
            
            # Additional debugging: Show the last few lines of logs
            if logs.strip():
                lines = logs.strip().split('\n')
                last_lines = lines[-10:] if len(lines) > 10 else lines
                logger.info("last_lines_of_logs", last_lines=last_lines)
                
                # Look for any lines that might contain JSON
                json_candidates = []
                for i, line in enumerate(lines):
                    # Clean the line of control characters first
                    clean_line = ''.join(char for char in line if ord(char) >= 32 or char in '\n\r\t')
                    if clean_line.strip().startswith('{') and clean_line.strip().endswith('}'):
                        json_candidates.append(f"Line {i+1}: {clean_line.strip()}")
                
                if json_candidates:
                    logger.info("json_candidates_found", candidates=json_candidates)
                else:
                    logger.warning("no_json_candidates_found")
            
            # Clean up the container after capturing logs
            await self.cleanup_container(container_id)
            
            # Parse the result
            exit_code = result.get('StatusCode', 1)
            
            if exit_code == 0:
                # Parse JSON result from logs
                import json
                try:
                    # Find JSON result in logs
                    lines = logs.strip().split('\n')
                    logger.info("parsing_logs", lines_count=len(lines))
                    
                    # First, try to find the last valid JSON line (most likely the scan result)
                    json_result = None
                    
                    # Look for JSON in reverse order (latest results first)
                    for line in reversed(lines):
                        line = line.strip()
                        if not line:
                            continue
                            
                        # Skip debug lines and non-JSON content
                        if line.startswith('DEBUG:') or line.startswith('ERROR:') or line.startswith('INFO:'):
                            continue
                            
                        # Look for JSON pattern - be more specific
                        if line.startswith('{') and line.endswith('}'):
                            try:
                                # Clean the line of any control characters
                                clean_line = ''.join(char for char in line if ord(char) >= 32 or char in '\n\r\t')
                                result_data = json.loads(clean_line)
                                
                                # Validate this looks like a scan result
                                if isinstance(result_data, dict) and 'safe' in result_data:
                                    json_result = result_data
                                    logger.info("json_found_reverse", result_data=result_data)
                                    break
                            except json.JSONDecodeError:
                                # Try with more aggressive cleaning
                                try:
                                    # Remove all non-printable characters except newlines and tabs
                                    aggressive_clean = ''.join(char for char in line if char.isprintable() or char in '\n\r\t')
                                    result_data = json.loads(aggressive_clean)
                                    if isinstance(result_data, dict) and 'safe' in result_data:
                                        json_result = result_data
                                        logger.info("json_found_reverse_aggressive", result_data=result_data)
                                        break
                                except json.JSONDecodeError:
                                    continue
                    
                    # If no valid JSON found in reverse, try forward search
                    if not json_result:
                        for line in lines:
                            line = line.strip()
                            if not line:
                                continue
                                
                            # Skip debug lines
                            if line.startswith('DEBUG:') or line.startswith('ERROR:') or line.startswith('INFO:'):
                                continue
                                
                            # Look for JSON pattern
                            if line.startswith('{') and line.endswith('}'):
                                try:
                                    # Clean the line of any control characters
                                    clean_line = ''.join(char for char in line if ord(char) >= 32 or char in '\n\r\t')
                                    result_data = json.loads(clean_line)
                                    
                                    # Validate this looks like a scan_result
                                    if isinstance(result_data, dict) and 'safe' in result_data:
                                        json_result = result_data
                                        logger.info("json_found_forward", result_data=result_data)
                                        break
                                except json.JSONDecodeError:
                                    # Try with more aggressive cleaning
                                    try:
                                        # Remove all non-printable characters except newlines and tabs
                                        aggressive_clean = ''.join(char for char in line if char.isprintable() or char in '\n\r\t')
                                        result_data = json.loads(aggressive_clean)
                                        if isinstance(result_data, dict) and 'safe' in result_data:
                                            json_result = result_data
                                            logger.info("json_found_forward_aggressive", result_data=result_data)
                                            break
                                    except json.JSONDecodeError:
                                        continue
                    
                    # If still no result, try to find any JSON in the logs
                    if not json_result:
                        # Look for JSON pattern anywhere in the logs
                        import re
                        # Clean logs of control characters first
                        clean_logs = ''.join(char for char in logs if ord(char) >= 32 or char in '\n\r\t')
                        json_matches = re.findall(r'\{[^{}]*\}', clean_logs)
                        for match in reversed(json_matches):
                            try:
                                result_data = json.loads(match)
                                if isinstance(result_data, dict) and 'safe' in result_data:
                                    json_result = result_data
                                    logger.info("json_found_regex", result_data=result_data)
                                    break
                            except json.JSONDecodeError:
                                continue
                        
                        # If still no result, try to extract JSON from the raw logs with control characters
                        if not json_result:
                            try:
                                # Look for JSON pattern in raw logs, handling control characters
                                raw_json_matches = re.findall(r'\{[^{}]*\}', logs)
                                for match in raw_json_matches:
                                    try:
                                        # Remove all control characters except newlines and tabs
                                        clean_match = ''.join(char for char in match if char.isprintable() or char in '\n\r\t')
                                        result_data = json.loads(clean_match)
                                        if isinstance(result_data, dict) and 'safe' in result_data:
                                            json_result = result_data
                                            logger.info("json_found_raw_regex", result_data=result_data)
                                            break
                                    except json.JSONDecodeError:
                                        continue
                            except Exception as e:
                                logger.warning("raw_json_extraction_failed", error=str(e))
                    
                    if json_result:
                        logger.info("json_extraction_successful", result=json_result)
                        return {
                            'success': True,
                            'result': json_result,
                            'logs': logs
                        }
                    
                    # Log detailed information about what we found
                    logger.error("no_valid_json_found", 
                               logs_length=len(logs),
                               logs_preview=logs[:500],
                               logs_end=logs[-500:] if len(logs) > 500 else logs)
                    
                    # Try to find any JSON-like content for debugging
                    import re
                    potential_json = re.findall(r'\{[^{}]*\}', logs)
                    logger.error("potential_json_found", count=len(potential_json), samples=potential_json[:3])
                    
                    return {
                        'success': False,
                        'error': 'No valid JSON scan result found in logs',
                        'logs': logs
                    }
                except json.JSONDecodeError as e:
                    logger.error("json_parse_error", error=str(e), logs=logs)
                    return {
                        'success': False,
                        'error': f'Failed to parse scan result: {str(e)}',
                        'logs': logs
                    }
            else:
                logger.error("container_failed", exit_code=exit_code, logs=logs)
                return {
                    'success': False,
                    'error': f'Container failed with exit code {exit_code}',
                    'logs': logs
                }
                
        except Exception as e:
            logger.error("container_wait_failed", container_id=container_id, error=str(e))
            return {
                'success': False,
                'error': f'Container wait failed: {str(e)}',
                'logs': ''
            }
    
    async def capture_container_logs_during_execution(self, container_id: str, timeout: int) -> str:
        """
        Capture container logs during execution, not just after completion.
        This method provides an additional fallback for Linux servers.
        """
        try:
            client = self._get_docker_client()
            logs_buffer = []
            
            # Monitor container and capture logs every 500ms
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    # Check if container is still running
                    response = client._request('GET', f'/v1.41/containers/{container_id}/json')
                    if response.status_code == 200:
                        container_info = response.json()
                        if not container_info.get('State', {}).get('Running', False):
                            break  # Container finished
                    
                    # Get current logs
                    current_logs = client.get_container_logs(container_id) or ''
                    if current_logs.strip():
                        new_lines = current_logs.strip().split('\n')
                        for line in new_lines:
                            if line.strip() and line not in logs_buffer:
                                logs_buffer.append(line)
                    
                    await asyncio.sleep(0.5)  # 500ms interval
                    
                except Exception as e:
                    logger.warning("log_capture_error", container_id=container_id, error=str(e))
                    await asyncio.sleep(1)
            
            # Get final logs
            final_logs = client.get_container_logs(container_id) or ''
            if final_logs.strip():
                final_lines = final_logs.strip().split('\n')
                for line in final_lines:
                    if line.strip() and line not in logs_buffer:
                        logs_buffer.append(line)
            
            return '\n'.join(logs_buffer)
                
        except Exception as e:
            logger.error("capture_container_logs_during_execution_error", container_id=container_id, error=str(e))
            return ""
    
    async def scan_file_in_container(self, file_path: Path) -> ContainerScanResult:
        """Scan a file using a fresh container."""
        start_time = time.time()
        container_id = None
        
        try:
            # Calculate file hash for unique identification
            import hashlib
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5(f.read()).hexdigest()
            
            # Create fresh container
            container_id = await self.create_scan_container(file_path, file_hash)
            if not container_id:
                return ContainerScanResult(
                    safe=True,
                    threats=[],
                    scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    scan_duration_ms=int((time.time() - start_time) * 1000),
                    container_duration_ms=0, # Placeholder, will be updated after wait
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine="container_ensemble",
                    error="Failed to create scan container"
                )
            
            # Wait for completion
            result = await self.wait_for_container_completion(container_id, self.scan_timeout)
            
            # Calculate scan duration
            scan_duration_ms = int((time.time() - start_time) * 1000)
            
            if result['success']:
                # Extract timing information from the scan worker's JSON response
                scan_result = result['result']
                
                # Get the pure scanning time from the container (excluding initialization)
                pure_scan_duration_ms = scan_result.get('scanDurationMs', 0)
                
                # Get the total container time from the container (including all overhead)
                container_duration_ms = scan_result.get('containerDurationMs', 0)
                
                # If container didn't provide timing, fall back to our measurement
                if container_duration_ms == 0:
                    container_duration_ms = scan_duration_ms
                
                return ContainerScanResult(
                    safe=scan_result.get('safe', True),
                    threats=scan_result.get('threats', []),
                    scan_time=scan_result.get('scanTime', time.strftime("%Y-%m-%dT%H:%M:%S")),
                    scan_duration_ms=pure_scan_duration_ms,  # Pure scanning time (excluding initialization)
                    container_duration_ms=container_duration_ms,  # Total container time including all overhead
                    file_size=scan_result.get('fileSize', file_path.stat().st_size),
                    file_name=scan_result.get('fileName', file_path.name),
                    scan_engine=scan_result.get('scanEngine', 'container_ensemble')
                )
            else:
                return ContainerScanResult(
                    safe=True,
                    threats=[],
                    scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    scan_duration_ms=scan_duration_ms,
                    container_duration_ms=0, # Placeholder, will be updated after wait
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine="container_ensemble",
                    error=result['error']
                )
                
        except Exception as e:
            logger.error("container_scan_failed", error=str(e), file_path=str(file_path))
            return ContainerScanResult(
                safe=True,
                threats=[],
                scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                scan_duration_ms=int((time.time() - start_time) * 1000),
                container_duration_ms=0, # Placeholder, will be updated after wait
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine="container_ensemble",
                error=f"Container scan failed: {str(e)}"
            )
        finally:
            # Always cleanup container
            if container_id:
                await self.cleanup_container(container_id)

    async def scan_file_stream(self, upload_file) -> ContainerScanResult:
        """Scan a file by streaming it directly to a child container without saving to main container."""
        start_time = time.time()
        container_id = None
        
        try:
            # Validate file size during streaming
            file_size = 0
            chunk_size = 64 * 1024  # 64KB chunks for streaming
            max_size_bytes = settings.MAX_FILE_SIZE_MB * 1024 * 1024
            
            # Create fresh container for streaming
            container_id = await self.create_streaming_container(upload_file.filename)
            if not container_id:
                return ContainerScanResult(
                    safe=True,
                    threats=[],
                    scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    scan_duration_ms=int((time.time() - start_time) * 1000),
                    container_duration_ms=0,
                    file_size=0,
                    file_name=upload_file.filename,
                    scan_engine="container_ensemble",
                    error="Failed to create streaming container"
                )
            
            # Stream file content directly to container
            logger.info("starting_file_stream", container_id=container_id, filename=upload_file.filename)
            
            # Create tar archive in memory and stream to container
            import tarfile
            import io
            
            # First pass: read entire file to get size and validate
            file_chunks = []
            while chunk := await upload_file.read(chunk_size):
                file_size += len(chunk)
                
                # Check file size limit
                if file_size > max_size_bytes:
                    await self.cleanup_container(container_id)
                    raise HTTPException(
                        status_code=413,
                        detail=f"File too large. Maximum size is {settings.MAX_FILE_SIZE_MB}MB"
                    )
                
                file_chunks.append(chunk)
            
            # Create tar archive with complete file
            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                # Create tarinfo for the file
                tarinfo = tarfile.TarInfo(name=upload_file.filename)
                tarinfo.size = file_size
                tarinfo.mode = 0o644
                
                # Combine all chunks and add to tar
                file_data = b''.join(file_chunks)
                tar.addfile(tarinfo, io.BytesIO(file_data))
            
            # Get tar data
            tar_buffer.seek(0)
            tar_data = tar_buffer.getvalue()
            
            # Copy tar archive to container
            client = self._get_docker_client()
            logger.info("attempting_file_copy", container_id=container_id, tar_size=len(tar_data), filename=upload_file.filename)
            
            # Check if container is still running before copying
            container_status = client.get_container_status(container_id)
            logger.info("container_status_before_copy", container_id=container_id, status=container_status)
            
            # If container is not running, try to restart it
            if container_status != "running":
                logger.warning("container_not_running_before_copy", container_id=container_id, status=container_status)
                # Try to start the container again
                if client.start_container(container_id):
                    logger.info("container_restarted_successfully", container_id=container_id)
                    # Wait a moment for container to fully start
                    await asyncio.sleep(1)
                    container_status = client.get_container_status(container_id)
                    logger.info("container_status_after_restart", container_id=container_id, status=container_status)
                else:
                    logger.error("failed_to_restart_container", container_id=container_id)
                    await self.cleanup_container(container_id)
                    return ContainerScanResult(
                        safe=True,
                        threats=[],
                        scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                        scan_duration_ms=int((time.time() - start_time) * 1000),
                        container_duration_ms=0,
                        file_size=file_size,
                        file_name=upload_file.filename,
                        scan_engine="container_ensemble",
                        error="Container not running and failed to restart"
                    )
            
            if not client.put_archive(container_id, '/scan', tar_data):
                logger.error("failed_to_copy_streamed_file", container_id=container_id, tar_size=len(tar_data))
                await self.cleanup_container(container_id)
                return ContainerScanResult(
                    safe=True,
                    threats=[],
                    scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    scan_duration_ms=int((time.time() - start_time) * 1000),
                    container_duration_ms=0,
                    file_size=file_size,
                    file_name=upload_file.filename,
                    scan_engine="container_ensemble",
                    error="Failed to copy streamed file to container"
                )
            
            logger.info("file_streamed_to_container", container_id=container_id, filename=upload_file.filename, file_size=file_size)
            
            # Now execute the scan command in the running container
            logger.info("executing_scan_command", container_id=container_id, filename=upload_file.filename)
            exec_result = client.exec_in_container(container_id, ['/start.sh'])
            if not exec_result or exec_result.get('ExitCode', 1) != 0:
                logger.error("scan_execution_failed", container_id=container_id, exit_code=exec_result.get('ExitCode', 1))
                await self.cleanup_container(container_id)
                return ContainerScanResult(
                    safe=True,
                    threats=[],
                    scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    scan_duration_ms=int((time.time() - start_time) * 1000),
                    container_duration_ms=0,
                    file_size=file_size,
                    file_name=upload_file.filename,
                    scan_engine="container_ensemble",
                    error="Failed to execute scan command"
                )
            
            # Get the scan result from the execution output
            scan_output = exec_result.get('Output', '')
            logger.info("scan_execution_completed", container_id=container_id, output_length=len(scan_output))
            
            # Parse the JSON result from the scan output
            try:
                # Find the JSON result in the output (it should be the last line)
                lines = scan_output.strip().split('\n')
                json_result = None
                for line in reversed(lines):
                    if line.strip().startswith('{') and line.strip().endswith('}'):
                        json_result = json.loads(line.strip())
                        break
                
                if json_result:
                    return ContainerScanResult(
                        safe=json_result.get('safe', True),
                        threats=json_result.get('threats', []),
                        scan_time=json_result.get('scanTime', time.strftime("%Y-%m-%dT%H:%M:%S")),
                        scan_duration_ms=json_result.get('scanDurationMs', 0),
                        container_duration_ms=json_result.get('containerDurationMs', 0),
                        file_size=json_result.get('fileSize', file_size),
                        file_name=json_result.get('fileName', upload_file.filename),
                        scan_engine=json_result.get('scanEngine', 'container_ensemble')
                    )
                else:
                    logger.error("no_json_result_found", container_id=container_id, output=scan_output[:500])
                    return ContainerScanResult(
                        safe=True,
                        threats=[],
                        scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                        scan_duration_ms=int((time.time() - start_time) * 1000),
                        container_duration_ms=0,
                        file_size=file_size,
                        file_name=upload_file.filename,
                        scan_engine="container_ensemble",
                        error="No valid scan result found in output"
                    )
            except json.JSONDecodeError as e:
                logger.error("json_parse_error", container_id=container_id, error=str(e), output=scan_output[:500])
                return ContainerScanResult(
                    safe=True,
                    threats=[],
                    scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    scan_duration_ms=int((time.time() - start_time) * 1000),
                    container_duration_ms=0,
                    file_size=file_size,
                    file_name=upload_file.filename,
                    scan_engine="container_ensemble",
                    error=f"Failed to parse scan result: {str(e)}"
                )
                
        except Exception as e:
            logger.error("streaming_scan_failed", error=str(e), filename=upload_file.filename)
            return ContainerScanResult(
                safe=True,
                threats=[],
                scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                scan_duration_ms=int((time.time() - start_time) * 1000),
                container_duration_ms=0,
                file_size=0,
                file_name=upload_file.filename,
                scan_engine="container_ensemble",
                error=f"Streaming scan failed: {str(e)}"
            )
        finally:
            # Always cleanup container
            if container_id:
                await self.cleanup_container(container_id)


    async def execute_python_code(self, python_code: str, timeout: int = 300) -> ContainerScanResult:
        """
        Execute Python code by piping it into a container without storing the source code.
        
        Args:
            python_code: Python source code as string
            timeout: Execution timeout in seconds
            
        Returns:
            ContainerScanResult with execution results
        """
        start_time = time.time()
        container_id = None
        
        try:
            # Create container for Python execution
            client = self._get_docker_client()
            
            container_config = {
                'image': self.container_image,
                'command': ['/bin/bash'],  # Just start bash, we'll execute commands via exec
                'volumes': {
                    str(Path(settings.YARA_RULES_PATH).parent): {'bind': '/app/rules', 'mode': 'ro'}
                },
                'environment': {
                    'MAX_FILE_SIZE_MB': str(settings.MAX_FILE_SIZE_MB),
                    'SCAN_TIMEOUT_SECONDS': str(settings.SCAN_TIMEOUT_SECONDS),
                    'ML_ENABLE_PE_ANALYSIS': str(settings.ML_ENABLE_PE_ANALYSIS),
                    'ML_ENABLE_ENTROPY_ANALYSIS': str(settings.ML_ENABLE_ENTROPY_ANALYSIS),
                    'SCAN_TIMEOUT': str(timeout),
                    'SCAN_MODE': 'python_execution',
                    # Pass through HMAC configuration
                    'HMAC_SECRET_KEY': os.environ.get('HMAC_SECRET_KEY', ''),
                    'HMAC_ENABLED': str(settings.HMAC_ENABLED),
                    'HMAC_TIMESTAMP_TOLERANCE_SECONDS': str(settings.HMAC_TIMESTAMP_TOLERANCE_SECONDS),
                    # Pass through other configurations
                    'MALWAREBazaar_API_KEY': os.environ.get('MALWAREBazaar_API_KEY', ''),
                    'MALWAREBazaar_API_KEY_BACKUP': os.environ.get('MALWAREBazaar_API_KEY_BACKUP', ''),
                    'MALWAREBazaar_ENABLED': str(settings.MALWAREBazaar_ENABLED),
                    'MALWAREBazaar_TIMEOUT': str(settings.MALWAREBazaar_TIMEOUT),
                    'BYTESCALE_API_KEY': os.environ.get('BYTESCALE_API_KEY', ''),
                    'BYTESCALE_ACCOUNT_ID': os.environ.get('BYTESCALE_ACCOUNT_ID', ''),
                    'BYTESCALE_ENABLED': str(settings.BYTESCALE_ENABLED),
                    'BYTESCALE_TIMEOUT': str(settings.BYTESCALE_TIMEOUT)
                },
                'mem_limit': self.max_memory,
                'cpu_period': 100000,
                'cpu_quota': int(float(self.max_cpu) * 100000),
                'network_disabled': False,
                'read_only': False,
                'tmpfs': {'/tmp': 'size=100m'},  # Temporary filesystem (reduced since ClamAV DBs are now shared)
                'detach': False,
                'AutoRemove': False,
                'stdin_open': True,  # Enable stdin for piping
                'tty': False
            }
            
            # Create and start container
            container_id = client.create_container(container_config)
            if not container_id:
                logger.error("python_execution_container_creation_failed")
                return ContainerScanResult(
                    safe=True,
                    threats=[],
                    scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    scan_duration_ms=0,
                    container_duration_ms=0,
                    file_size=len(python_code.encode()),
                    file_name='python_script.py',
                    scan_engine="container_ensemble",
                    error="Failed to create Python execution container"
                )
            
            if not client.start_container(container_id):
                logger.error("python_execution_container_start_failed", container_id=container_id)
                client.remove_container(container_id, force=True)
                return ContainerScanResult(
                    safe=True,
                    threats=[],
                    scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    scan_duration_ms=0,
                    container_duration_ms=0,
                    file_size=len(python_code.encode()),
                    file_name='python_script.py',
                    scan_engine="container_ensemble",
                    error="Failed to start Python execution container"
                )
            
            # Step 1: Write Python code to temporary file using put_archive
            logger.info("writing_python_code_to_container", container_id=container_id, code_length=len(python_code))
            
            # Create a tar archive with the Python code
            import tarfile
            import io
            
            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                # Create tarinfo for the Python script
                tarinfo = tarfile.TarInfo(name='script.py')
                tarinfo.size = len(python_code.encode())
                tarinfo.mode = 0o644
                
                # Add the Python code to the tar
                tar.addfile(tarinfo, io.BytesIO(python_code.encode()))
            
            # Copy the tar archive to the container's /tmp directory
            tar_buffer.seek(0)
            if not client.put_archive(container_id, '/tmp', tar_buffer.getvalue()):
                logger.error("failed_to_write_python_code", container_id=container_id)
                return ContainerScanResult(
                    safe=True,
                    threats=[],
                    scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    scan_duration_ms=0,
                    container_duration_ms=int((time.time() - start_time) * 1000),
                    file_size=len(python_code.encode()),
                    file_name='python_script.py',
                    scan_engine="container_ensemble",
                    error="Failed to write Python code to container using put_archive"
                )
            
            # Step 2: Execute the Python script
            logger.info("executing_python_script", container_id=container_id)
            exec_result = client.exec_in_container(
                container_id, 
                ['/bin/bash', '-c', 'python /tmp/script.py']
            )
            
            if not exec_result:
                logger.error("python_execution_failed", container_id=container_id, error="No execution result")
                return ContainerScanResult(
                    safe=True,
                    threats=[],
                    scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                    scan_duration_ms=0,
                    container_duration_ms=int((time.time() - start_time) * 1000),
                    file_size=len(python_code.encode()),
                    file_name='python_script.py',
                    scan_engine="container_ensemble",
                    error="Python execution failed: No execution result"
                )
            
            # Step 3: Clean up the temporary file
            logger.info("cleaning_up_temporary_file", container_id=container_id)
            cleanup_result = client.exec_in_container(
                container_id, 
                ['/bin/bash', '-c', 'rm -f /tmp/script.py && echo "File cleaned up"']
            )
            
            if not cleanup_result or cleanup_result.get('ExitCode', 1) != 0:
                logger.warning("failed_to_cleanup_temp_file", container_id=container_id, 
                             exit_code=cleanup_result.get('ExitCode', 'unknown') if cleanup_result else 'unknown')
            else:
                logger.info("temporary_file_cleaned_up_successfully", container_id=container_id)
            
            # Get execution output
            stdout = exec_result.get('stdout', '')
            stderr = exec_result.get('stderr', '')
            exit_code = exec_result.get('ExitCode', 1)
            
            # Analyze the output for potential threats
            threats = []
            if stderr:
                threats.append(f"Python execution warnings/errors: {stderr}")
            
            if exit_code != 0:
                threats.append(f"Python execution failed with exit code {exit_code}")
            
            # Check if code contains suspicious patterns
            suspicious_patterns = ['import os', 'import subprocess', 'import sys', 'eval(', 'exec(', '__import__']
            for pattern in suspicious_patterns:
                if pattern in python_code:
                    threats.append(f"Suspicious Python pattern detected: {pattern}")
            
            # Determine if execution was safe
            is_safe = len(threats) == 0 and exit_code == 0
            
            execution_duration_ms = int((time.time() - start_time) * 1000)
            
            logger.info("python_execution_completed", container_id=container_id, 
                       safe=is_safe, threats_count=len(threats), exit_code=exit_code)
            
            return ContainerScanResult(
                safe=is_safe,
                threats=threats,
                scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                scan_duration_ms=execution_duration_ms,
                container_duration_ms=execution_duration_ms,
                file_size=len(python_code.encode()),
                file_name='python_script.py',
                scan_engine="container_ensemble",
                details={
                    'stdout': stdout,
                    'stderr': stderr,
                    'execution_successful': exit_code == 0,
                    'exit_code': exit_code
                }
            )
            
        except Exception as e:
            logger.error("python_execution_failed", error=str(e))
            return ContainerScanResult(
                safe=True,
                threats=[],
                scan_time=time.strftime("%Y-%m-%dT%H:%M:%S"),
                scan_duration_ms=0,
                container_duration_ms=int((time.time() - start_time) * 1000),
                file_size=len(python_code.encode()) if python_code else 0,
                file_name='python_script.py',
                scan_engine="container_ensemble",
                error=f"Python execution failed: {str(e)}"
            )
        finally:
            # Always cleanup container
            if container_id:
                await self.cleanup_container(container_id)


# Global container manager instance
container_manager = ContainerManager() 