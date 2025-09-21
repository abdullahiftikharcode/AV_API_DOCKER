import requests
import json
import time
import os
import asyncio
import structlog
import http.client
import socket
from typing import Optional, Dict, Any, List
from app.config import settings

logger = structlog.get_logger()

class UnixSocketConnection(http.client.HTTPConnection):
    def __init__(self, socket_path):
        super().__init__('localhost')
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.socket_path)
        self.sock = sock

class UnixSocketAdapter(requests.adapters.BaseAdapter):
    def __init__(self, socket_path):
        self.socket_path = socket_path

    def get_connection(self, url, proxies=None):
        return UnixSocketConnection(self.socket_path)

    def close(self):
        pass

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        conn = self.get_connection(request.url)
        conn.timeout = timeout

        try:
            conn.request(
                method=request.method,
                url=request.path_url,
                body=request.body,
                headers=request.headers,
            )
            resp = conn.getresponse()
            r = requests.Response()
            r.status_code = resp.status
            r.headers = dict(resp.getheaders())
            r.raw = resp
            r.reason = resp.reason
            r._content = resp.read()
            return r
        except Exception as e:
            raise requests.exceptions.RequestException(e)

class DockerClient:
    def __init__(self, socket_path: str = '/var/run/docker.sock'):
        self.session = requests.Session()
        self.session.mount('http+unix://', UnixSocketAdapter(socket_path))
        self.base_url = 'http+unix://localhost'

    def _request(self, method: str, path: str, **kwargs) -> requests.Response:
        url = f"{self.base_url}{path}"
        return self.session.request(method, url, **kwargs)

    def ping(self) -> bool:
        try:
            response = self._request('GET', '/_ping')
            return response.status_code == 200
        except:
            return False

    def version(self) -> Dict[str, Any]:
        response = self._request('GET', '/version')
        return response.json()

    def create_container(self, config: Dict[str, Any]) -> Optional[str]:
        try:
            logger.info("docker_create_container", image=config.get('image'), command=config.get('command', []))
            
            # Use simpler Docker API structure that matches working pattern
            container_config = {
                'Image': config.get('image'),
                'Cmd': config.get('command', []),
                'Env': [f"{k}={v}" for k, v in config.get('environment', {}).items()],
                'HostConfig': {
                    'Binds': [],
                    'Memory': self._parse_memory_limit(config.get('mem_limit', '8g')),
                    'CpuPeriod': config.get('cpu_period', 100000),
                    'CpuQuota': config.get('cpu_quota', 200000),
                    'NetworkMode': 'none' if config.get('network_disabled', True) else 'bridge',
                    'ReadonlyRootfs': config.get('read_only', False),
                    'Tmpfs': config.get('tmpfs', {}),
                    'AutoRemove': config.get('AutoRemove', False),  # Use passed config or default to False
                    'Privileged': False,
                    # Temporarily remove security restrictions for streaming containers
                    # 'CapDrop': ['AUDIT_WRITE', 'CHOWN', 'DAC_OVERRIDE', 'FOWNER', 'FSETID', 'KILL', 'MKNOD', 'NET_RAW', 'SETGID', 'SETUID', 'SYS_CHROOT'],
                    # 'SecurityOpt': ['no-new-privileges'],
                    'Dns': ['8.8.8.8', '1.1.1.1']  # Add DNS servers for name resolution
                }
            }
            
            # Handle volume bindings
            if config.get('volumes'):
                binds = []
                for host_path, bind_info in config['volumes'].items():
                    if isinstance(bind_info, dict):
                        container_path = bind_info.get('bind', host_path)
                        mode = bind_info.get('mode', 'rw')
                        binds.append(f"{host_path}:{container_path}:{mode}")
                    else:
                        binds.append(f"{host_path}:{bind_info}:rw")
                container_config['HostConfig']['Binds'] = binds
            
            # Clean up empty values
            container_config = {k: v for k, v in container_config.items() if v is not None and v != []}
            container_config['HostConfig'] = {k: v for k, v in container_config['HostConfig'].items() if v is not None and v != []}
            
            logger.info("docker_create_container_final_config", image=container_config.get('Image'), command=container_config.get('Cmd', []))
            
            response = self._request(
                'POST',
                '/v1.41/containers/create',
                headers={'Content-Type': 'application/json'},
                data=json.dumps(container_config)
            )
            logger.info("docker_create_response", status_code=response.status_code, response=response.text)
            if response.status_code == 201:
                container_id = response.json()['Id']
                logger.info("container_created_successfully", container_id=container_id)
                return container_id
            logger.error("container_creation_failed", status_code=response.status_code, response=response.text)
            return None
        except Exception as e:
            logger.error("container_creation_exception", error=str(e))
            return None

    def _parse_memory_limit(self, memory_limit: str) -> int:
        """Convert memory limit string to bytes."""
        if isinstance(memory_limit, int):
            return memory_limit
        
        memory_limit = str(memory_limit).lower()
        if memory_limit.endswith('g'):
            return int(float(memory_limit[:-1]) * 1024 * 1024 * 1024)
        elif memory_limit.endswith('m'):
            return int(float(memory_limit[:-1]) * 1024 * 1024)
        elif memory_limit.endswith('k'):
            return int(float(memory_limit[:-1]) * 1024)
        else:
            return int(memory_limit)

    def start_container(self, container_id: str) -> bool:
        try:
            logger.info("docker_start_container", container_id=container_id)
            response = self._request('POST', f'/v1.41/containers/{container_id}/start')
            logger.info("docker_start_response", container_id=container_id, status_code=response.status_code)
            return response.status_code == 204
        except Exception as e:
            logger.error("container_start_exception", container_id=container_id, error=str(e))
            return False

    def stop_container(self, container_id: str, timeout: int = 10) -> bool:
        try:
            response = self._request('POST', f'/v1.41/containers/{container_id}/stop?t={timeout}')
            return response.status_code in (204, 304)
        except:
            return False

    def remove_container(self, container_id: str, force: bool = False) -> bool:
        try:
            response = self._request('DELETE', f'/v1.41/containers/{container_id}?force={str(force).lower()}')
            return response.status_code == 204
        except:
            return False

    def get_container_logs(self, container_id: str, stdout: bool = True, stderr: bool = True) -> Optional[str]:
        try:
            response = self._request(
                'GET',
                f'/v1.41/containers/{container_id}/logs?stdout={str(stdout).lower()}&stderr={str(stderr).lower()}'
            )
            if response.status_code == 200:
                return response.text
            return None
        except:
            return None

    def stream_container_logs(self, container_id: str, timeout: int = 300) -> Optional[str]:
        """
        Stream container logs in real-time and capture them.
        This method ensures logs are captured even on Linux servers where
        post-completion log retrieval might fail.
        """
        try:
            import threading
            from queue import Queue
            
            logs_buffer = []
            logs_queue = Queue()
            stop_streaming = threading.Event()
            
            def log_reader():
                """Background thread to continuously read logs"""
                try:
                    # Get logs every 100ms to capture real-time output
                    while not stop_streaming.is_set():
                        try:
                            response = self._request(
                                'GET',
                                f'/v1.41/containers/{container_id}/logs?stdout=true&stderr=true&tail=100'
                            )
                            if response.status_code == 200 and response.text.strip():
                                # Split logs into lines and add new ones
                                new_lines = response.text.strip().split('\n')
                                for line in new_lines:
                                    if line.strip() and line not in logs_buffer:
                                        logs_buffer.append(line)
                                        logs_queue.put(line)
                            time.sleep(0.1)  # 100ms interval
                        except Exception as e:
                            logger.warning("log_streaming_error", container_id=container_id, error=str(e))
                            time.sleep(0.5)  # Longer interval on error
                except Exception as e:
                    logger.error("log_reader_thread_error", container_id=container_id, error=str(e))
            
            # Start background log reader
            reader_thread = threading.Thread(target=log_reader, daemon=True)
            reader_thread.start()
            
            # Wait for container completion or timeout
            start_time = time.time()
            while time.time() - start_time < timeout:
                # Check if container is still running
                try:
                    response = self._request('GET', f'/v1.41/containers/{container_id}/json')
                    if response.status_code == 200:
                        container_info = response.json()
                        if not container_info.get('State', {}).get('Running', False):
                            break  # Container finished
                except:
                    pass
                
                time.sleep(0.5)
            
            # Stop streaming and wait for thread to finish
            stop_streaming.set()
            reader_thread.join(timeout=2)
            
            # Get final logs
            final_logs = self.get_container_logs(container_id) or ''
            
            # Combine streamed logs with final logs
            all_logs = '\n'.join(logs_buffer)
            if final_logs:
                all_logs += '\n' + final_logs
            
            # Remove duplicates while preserving order
            seen = set()
            unique_logs = []
            for line in all_logs.split('\n'):
                if line.strip() and line not in seen:
                    seen.add(line)
                    unique_logs.append(line)
            
            return '\n'.join(unique_logs)
            
        except Exception as e:
            logger.error("stream_container_logs_error", container_id=container_id, error=str(e))
            # Fallback to regular log retrieval
            return self.get_container_logs(container_id)

    async def stream_container_logs_async(self, container_id: str, timeout: int = 300) -> Optional[str]:
        """Asynchronously stream container logs."""
        import asyncio
        
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, 
                lambda: self.stream_container_logs(container_id, timeout)
            )
            return result
        except Exception as e:
            logger.error("stream_container_logs_async_error", container_id=container_id, error=str(e))
            return None

    async def get_container_logs_async(self, container_id: str, stdout: bool = True, stderr: bool = True) -> Optional[str]:
        """Asynchronously get container logs."""
        import asyncio
        
        try:
            # Run the synchronous get_container_logs in a thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, 
                lambda: self.get_container_logs(container_id, stdout, stderr)
            )
            return result
        except Exception as e:
            logger.error("container_logs_error", container_id=container_id, error=str(e))
            return None

    def wait_container(self, container_id: str, timeout: Optional[int] = None) -> Optional[Dict[str, Any]]:
        try:
            response = self._request(
                'POST',
                f'/v1.41/containers/{container_id}/wait',
                timeout=timeout
            )
            if response.status_code == 200:
                return response.json()
            return None
        except:
            return None

    async def wait_container_async(self, container_id: str, timeout: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Asynchronously wait for container to complete."""
        import asyncio
        
        try:
            # Run the synchronous wait_container in a thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None, 
                lambda: self.wait_container(container_id, timeout)
            )
            return result
        except Exception as e:
            logger.error("container_wait_error", container_id=container_id, error=str(e))
            return None

    def exec_in_container(self, container_id: str, cmd: list, detach: bool = False, input_data: bytes = None) -> Optional[Dict[str, Any]]:
        try:
            # Create exec instance
            exec_config = {
                'Cmd': cmd,
                'AttachStdout': not detach,
                'AttachStderr': not detach,
                'AttachStdin': input_data is not None
            }
            logger.info("exec_in_container_creating", container_id=container_id, cmd=cmd, has_input=input_data is not None)
            response = self._request(
                'POST',
                f'/v1.41/containers/{container_id}/exec',
                headers={'Content-Type': 'application/json'},
                data=json.dumps(exec_config)
            )
            logger.info("exec_in_container_create_response", container_id=container_id, status_code=response.status_code, response=response.text)
            if response.status_code != 201:
                logger.error("exec_in_container_create_failed", container_id=container_id, status_code=response.status_code, response=response.text)
                return None
            exec_id = response.json()['Id']
            logger.info("exec_in_container_created", container_id=container_id, exec_id=exec_id)

            # Start exec instance with input data if provided
            start_data = {'Detach': detach}
            if input_data:
                start_data['Tty'] = False
                start_data['Privileged'] = False
                
                # Start the exec instance
                response = self._request(
                    'POST',
                    f'/v1.41/exec/{exec_id}/start',
                    headers={'Content-Type': 'application/json'},
                    data=json.dumps(start_data)
                )
                
                if response.status_code == 200:
                    # Send input data to the exec instance via stdin
                    # Note: Docker exec API doesn't support direct stdin piping in the way we need
                    # We'll use a different approach - write to a temporary file first
                    logger.warning("input_data_piping_not_supported", container_id=container_id, 
                                 exec_id=exec_id, data_size=len(input_data))
                    # For now, we'll return None to indicate input data isn't supported
                    # The container_manager will handle this by using put_archive instead
                    return None
                else:
                    logger.error("exec_in_container_start_failed", container_id=container_id, exec_id=exec_id, status_code=response.status_code)
                    return None
            else:
                # Start exec instance without input
                response = self._request(
                    'POST',
                    f'/v1.41/exec/{exec_id}/start',
                    headers={'Content-Type': 'application/json'},
                    data=json.dumps(start_data)
                )
                logger.info("exec_in_container_start_response", container_id=container_id, exec_id=exec_id, status_code=response.status_code)
                if response.status_code != 200:
                    logger.error("exec_in_container_start_failed", container_id=container_id, exec_id=exec_id, status_code=response.status_code)
                    return None

            # Wait for execution to complete with proper timeout
            import time
            max_wait_time = 300  # 5 minutes max
            check_interval = 2   # Check every 2 seconds
            waited = 0
            
            while waited < max_wait_time:
                time.sleep(check_interval)
                waited += check_interval
                
                # Check if exec is still running
                result_response = self._request('GET', f'/v1.41/exec/{exec_id}/json')
                if result_response.status_code == 200:
                    result = result_response.json()
                    if not result.get('Running', True):
                        # Execution completed
                        logger.info("exec_completed", container_id=container_id, exec_id=exec_id, exit_code=result.get('ExitCode', 0))
                        break
                else:
                    logger.warning("exec_status_check_failed", container_id=container_id, exec_id=exec_id, status_code=result_response.status_code)
            
            if waited >= max_wait_time:
                logger.warning("exec_timeout", container_id=container_id, exec_id=exec_id, waited_seconds=waited)
            
            # Get exec result
            response = self._request('GET', f'/v1.41/exec/{exec_id}/json')
            logger.info("exec_in_container_result_response", container_id=container_id, exec_id=exec_id, status_code=response.status_code)
            if response.status_code == 200:
                result = response.json()
                logger.info("exec_in_container_success", container_id=container_id, exec_id=exec_id, result=result)
                return result
            else:
                logger.error("exec_in_container_result_failed", container_id=container_id, exec_id=exec_id, status_code=response.status_code)
                return None
        except Exception as e:
            logger.error("exec_in_container_exception", container_id=container_id, error=str(e))
            return None

    def get_container_status(self, container_id: str) -> Optional[str]:
        """Get container status."""
        try:
            response = self._request('GET', f'/v1.41/containers/{container_id}/json')
            if response.status_code == 200:
                container_info = response.json()
                return container_info.get('State', {}).get('Status', 'unknown')
            return None
        except Exception as e:
            logger.error("get_container_status_exception", container_id=container_id, error=str(e))
            return None

    def put_file(self, container_id: str, local_file_path: str, container_path: str) -> bool:
        """Copy a file from host to container."""
        try:
            with open(local_file_path, 'rb') as f:
                file_data = f.read()
            
            # Create tar archive with the file
            import tarfile
            import io
            
            tar_buffer = io.BytesIO()
            with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
                tarinfo = tarfile.TarInfo(name=os.path.basename(container_path))
                tarinfo.size = len(file_data)
                tarinfo.mode = 0o644
                tar.addfile(tarinfo, io.BytesIO(file_data))
            
            tar_data = tar_buffer.getvalue()
            
            response = self._request(
                'PUT',
                f'/v1.41/containers/{container_id}/archive?path={os.path.dirname(container_path)}',
                headers={'Content-Type': 'application/x-tar'},
                data=tar_data
            )
            logger.info("put_file_response", container_id=container_id, local_path=local_file_path, container_path=container_path, status_code=response.status_code)
            if response.status_code != 200:
                logger.error("put_file_failed", container_id=container_id, status_code=response.status_code, response_text=response.text[:500])
            return response.status_code == 200
        except Exception as e:
            logger.error("put_file_exception", container_id=container_id, error=str(e))
            return False

    def put_archive(self, container_id: str, path: str, data: bytes) -> bool:
        try:
            response = self._request(
                'PUT',
                f'/v1.41/containers/{container_id}/archive?path={path}',
                headers={'Content-Type': 'application/x-tar'},
                data=data
            )
            logger.info("put_archive_response", container_id=container_id, path=path, status_code=response.status_code, data_size=len(data))
            if response.status_code != 200:
                logger.error("put_archive_failed", container_id=container_id, status_code=response.status_code, response_text=response.text[:500])
            return response.status_code == 200
        except Exception as e:
            logger.error("put_archive_exception", container_id=container_id, error=str(e))
            return False
