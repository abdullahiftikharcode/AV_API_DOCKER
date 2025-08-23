import subprocess
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
import os

from .base import BaseScanner, ScanResult
from ..config import settings
from ..utils.memory_manager import memory_manager


class ClamAVScanner(BaseScanner):
    """ClamAV antivirus scanner using clamscan command-line tool."""

    def __init__(self):
        super().__init__("ClamAV")
        self.version = "1.0"
        self.description = "ClamAV antivirus engine using shared virus definitions"
        self.clamscan_path = None

    async def initialize(self) -> None:
        """Initialize ClamAV scanner by finding clamscan binary."""
        try:
            # Try to find clamscan in common locations
            possible_paths = [
                '/usr/bin/clamscan',
                '/usr/local/bin/clamscan',
                '/opt/clamav/bin/clamscan',
                'clamscan'  # Try PATH
            ]
            
            for path in possible_paths:
                try:
                    result = subprocess.run([path, '--version'], capture_output=True, text=True, timeout=5)
                    if result.returncode == 0:
                        self.clamscan_path = path
                        print(f"DEBUG: ClamAV scanner initialized with clamscan at: {path}")
                        break
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    continue
            
            if not self.clamscan_path:
                raise Exception("clamscan binary not found in common locations")
            
            self.initialized = True
            print("DEBUG: ClamAV scanner initialized successfully")
            
        except Exception as e:
            print(f"ERROR: Failed to initialize ClamAV scanner: {e}")
            self.initialized = False

    def _convert_threat_to_human_readable(self, threat_name: str) -> str:
        """Convert ClamAV technical threat names to human-readable keywords."""
        threat_lower = threat_name.lower()
        
        # Common malware families and their human-readable names
        threat_mappings = {
            # Viruses
            'virus': 'Virus',
            'trojan': 'Trojan',
            'worm': 'Worm',
            'backdoor': 'Backdoor',
            'keylogger': 'Keylogger',
            'spyware': 'Spyware',
            'adware': 'Adware',
            'ransomware': 'Ransomware',
            'cryptominer': 'Cryptominer',
            'crypto_miner': 'Cryptominer',
            'miner': 'Cryptominer',
            
            # File types
            'exe': 'Executable',
            'dll': 'Library',
            'script': 'Script',
            'macro': 'Macro',
            'document': 'Document',
            
            # Specific threats
            'eicar': 'Test File',
            'test': 'Test File',
            'malware': 'Malware',
            'packed': 'Packed',
            'obfuscated': 'Obfuscated',
            'encrypted': 'Encrypted',
            'suspicious': 'Suspicious',
            
            # Common malware names
            'wannacry': 'Ransomware',
            'notpetya': 'Ransomware',
            'locky': 'Ransomware',
            'cerber': 'Ransomware',
            'cryptolocker': 'Ransomware',
            'zeus': 'Banking Trojan',
            'dridex': 'Banking Trojan',
            'emotet': 'Trojan',
            'trickbot': 'Banking Trojan',
            'ryuk': 'Ransomware',
            'sodinokibi': 'Ransomware',
            'maze': 'Ransomware',
            'doppelpaymer': 'Ransomware',
            'clop': 'Ransomware',
            'conti': 'Ransomware',
            'avaddon': 'Ransomware',
            'babuk': 'Ransomware',
            'blackcat': 'Ransomware',
            'alphv': 'Ransomware',
            'hive': 'Ransomware',
            'royal': 'Ransomware',
            'akira': 'Ransomware',
            '8base': 'Ransomware',
            'aes_niva': 'Ransomware',
            'aged': 'Ransomware',
            'agenda': 'Ransomware',
            'ahmose': 'Ransomware',
            'alice': 'Ransomware',
            'alpha': 'Ransomware',
            'amnesia': 'Ransomware',
            'anatova': 'Ransomware',
            'angry': 'Ransomware',
            'annabelle': 'Ransomware',
            'ant': 'Ransomware',
            'antares': 'Ransomware',
            'antlion': 'Ransomware',
            'apocalypse': 'Ransomware',
            'apt': 'Advanced Threat',
            'bad': 'Malware',
            'banker': 'Banking Trojan',
            'bot': 'Botnet',
            'browser': 'Browser Hijacker',
            'bunny': 'Ransomware',
            'c2': 'Command & Control',
            'cobalt': 'Cobalt Strike',
            'coin': 'Cryptominer',
            'crypto': 'Cryptominer',
            'dana': 'Ransomware',
            'dark': 'Dark Web',
            'djvu': 'Ransomware',
            'download': 'Downloader',
            'dropper': 'Dropper',
            'fake': 'Fake Software',
            'flood': 'Flooder',
            'game': 'Game Cheat',
            'generic': 'Generic Malware',
            'hack': 'Hacking Tool',
            'hacktool': 'Hacking Tool',
            'inject': 'Code Injector',
            'joke': 'Joke Program',
            'loader': 'Loader',
            'mal': 'Malware',
            'msil': 'MSIL Malware',
            'net': 'Network Malware',
            'nsis': 'NSIS Malware',
            'packer': 'Packer',
            'php': 'PHP Malware',
            'python': 'Python Malware',
            'rootkit': 'Rootkit',
            'shell': 'Shell',
            'stealer': 'Data Stealer',
            'swf': 'Flash Malware',
            'tool': 'Malicious Tool',
            'upx': 'Packed',
            'win': 'Windows Malware',
            'xored': 'Encrypted'
        }
        
        # Try to find a match in the threat mappings
        for key, human_name in threat_mappings.items():
            if key in threat_lower:
                return human_name
        
        # If no specific match found, try to extract meaningful parts
        if '.' in threat_name:
            # Split by dots and look for meaningful parts
            parts = threat_name.split('.')
            for part in parts:
                part_lower = part.lower()
                for key, human_name in threat_mappings.items():
                    if key in part_lower:
                        return human_name
        
        # If still no match, return a generic but readable description
        if any(word in threat_lower for word in ['win', 'msil', 'gen', 'generic']):
            return 'Windows Malware'
        elif any(word in threat_lower for word in ['unix', 'linux', 'elf']):
            return 'Linux Malware'
        elif any(word in threat_lower for word in ['android', 'apk', 'dex']):
            return 'Android Malware'
        elif any(word in threat_lower for word in ['mac', 'osx', 'apple']):
            return 'Mac Malware'
        else:
            return 'Malware'

    async def scan(self, file_path: Path) -> ScanResult:
        """Scan file using ClamAV."""
        start_time = datetime.now()
        
        try:
            if not self.initialized:
                raise Exception("ClamAV scanner not initialized")
            
            # Check memory pressure
            if warning := await memory_manager.check_memory_pressure():
                return ScanResult(
                    safe=True,  # Fail open on resource constraints
                    threats=[],
                    scan_time=datetime.now(timezone.utc),
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine=self.name,
                    confidence=0.0,
                    error=f"Memory pressure: {warning}"
                )

            # Perform scan using clamscan command
            cmd = [
                self.clamscan_path,
                '--no-summary',           # Don't show summary
                '--infected',              # Only show infected files
                '--suppress-ok-results',   # Don't show OK results
                '--database=/var/lib/clamav',  # Use shared virus databases from mounted volume
                str(file_path)
            ]
            
            # Run clamscan with timeout
            print(f"DEBUG: Running ClamAV command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout for large files
            )
            
            print(f"DEBUG: ClamAV return code: {result.returncode}")
            print(f"DEBUG: ClamAV stdout: {result.stdout.strip()}")
            print(f"DEBUG: ClamAV stderr: {result.stderr.strip()}")
            
            # Parse results
            threats = []
            is_clean = True
            
            if result.returncode == 0:
                # File is clean (no threats found)
                is_clean = True
            elif result.returncode == 1:
                # File is infected (threats found)
                is_clean = False
                # Parse threat information from stdout
                if result.stdout.strip():
                    threat_lines = result.stdout.strip().split('\n')
                    for line in threat_lines:
                        if line.strip() and ':' in line:
                            # Extract threat name from output like "file: ThreatName.UNOFFICIAL FOUND"
                            parts = line.split(':')
                            if len(parts) >= 2:
                                threat_name = parts[1].strip()
                                if 'FOUND' in threat_name:
                                    threat_name = threat_name.replace('FOUND', '').strip()
                                    # Convert to human-readable description
                                    human_readable_threat = self._convert_threat_to_human_readable(threat_name)
                                    threats.append(human_readable_threat)
            else:
                # Error occurred
                error_msg = result.stderr.strip() if result.stderr else f"clamscan failed with return code {result.returncode}"
                print(f"WARNING: ClamAV scan error: {error_msg}")
                # Fail open - assume file is safe on error
                is_clean = True

            return ScanResult(
                safe=is_clean,
                threats=threats,
                scan_time=datetime.now(timezone.utc),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=0.9 if threats else 0.6  # Higher confidence for positive detections
            )

        except subprocess.TimeoutExpired:
            return ScanResult(
                safe=True,  # Fail open on timeout
                threats=[],
                scan_time=datetime.now(timezone.utc),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=0.0,
                error="ClamAV scan timed out after 5 minutes"
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
                error=f"ClamAV scan failed: {str(e)}"
            )

    async def cleanup(self) -> None:
        """Cleanup ClamAV resources."""
        self.clamscan_path = None
        self.initialized = False 