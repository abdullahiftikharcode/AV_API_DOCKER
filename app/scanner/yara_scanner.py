import yara
import mmap
import asyncio
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Optional
import os
import re

from .base import BaseScanner, ScanResult
from ..config import settings
from ..utils.memory_manager import memory_manager


class YARAScanner(BaseScanner):
    """YARA pattern-based malware detection scanner."""

    def __init__(self):
        super().__init__("YARA")
        self.version = "1.0"
        self.description = "YARA pattern matching for malware detection"
        self.rules = None
        self._rules_cache = {}

    async def initialize(self) -> None:
        """Initialize YARA scanner by loading rules."""
        try:
            # Load YARA rules from the configured rules directory
            rules_dir = Path(settings.YARA_RULES_PATH)
            if not rules_dir.exists():
                print(f"WARNING: Rules directory not found: {rules_dir}")
                self.initialized = True
                return

            # Compile all YARA rules
            rule_files = list(rules_dir.rglob("*.yar")) + list(rules_dir.rglob("*.yara"))
            if not rule_files:
                print(f"WARNING: No YARA rule files found in {rules_dir}")
                self.initialized = True
                return

            # Compile rules
            compiled_rules = []
            for rule_file in rule_files:
                try:
                    rule = yara.compile(str(rule_file))
                    compiled_rules.append(rule)
                    print(f"DEBUG: Loaded YARA rule: {rule_file.name}")
                except Exception as e:
                    print(f"WARNING: Failed to compile YARA rule {rule_file}: {e}")

            if compiled_rules:
                # Combine all rules into one
                self.rules = yara.compile(source='\n'.join([rule.source for rule in compiled_rules]))
                print(f"DEBUG: YARA scanner initialized with {len(compiled_rules)} rules")
            else:
                print("WARNING: No YARA rules could be compiled")

            self.initialized = True
        except Exception as e:
            raise Exception(f"Failed to initialize YARA scanner: {str(e)}")

    def _get_rule_metadata(self, match) -> Dict[str, str]:
        """Extract metadata from YARA rule match."""
        metadata = {}
        if hasattr(match, 'meta'):
            metadata = match.meta
        return metadata

    def _convert_yara_rule_to_human_readable(self, rule_name: str, metadata: Dict[str, str]) -> str:
        """Convert YARA rule names and metadata to human-readable keywords."""
        rule_lower = rule_name.lower()
        
        # Common malware patterns and their human-readable names
        pattern_mappings = {
            # Malware types
            'ransomware': 'Ransomware',
            'trojan': 'Trojan',
            'virus': 'Virus',
            'worm': 'Worm',
            'backdoor': 'Backdoor',
            'keylogger': 'Keylogger',
            'spyware': 'Spyware',
            'adware': 'Adware',
            'cryptominer': 'Cryptominer',
            'miner': 'Cryptominer',
            'botnet': 'Botnet',
            'rootkit': 'Rootkit',
            'dropper': 'Dropper',
            'loader': 'Loader',
            'injector': 'Code Injector',
            'stealer': 'Data Stealer',
            'banker': 'Banking Trojan',
            'downloader': 'Downloader',
            'flooder': 'Flooder',
            'hacktool': 'Hacking Tool',
            'packer': 'Packer',
            'obfuscator': 'Obfuscator',
            'encryptor': 'Encryptor',
            
            # File types
            'exe': 'Executable',
            'dll': 'Library',
            'script': 'Script',
            'macro': 'Macro',
            'document': 'Document',
            'pdf': 'PDF',
            'office': 'Office Document',
            'flash': 'Flash',
            'java': 'Java',
            'android': 'Android',
            'ios': 'iOS',
            
            # Specific malware families
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
            'xored': 'Encrypted',
            
            # Behavioral patterns
            'persistence': 'Persistence',
            'lateral': 'Lateral Movement',
            'privilege': 'Privilege Escalation',
            'defense': 'Defense Evasion',
            'discovery': 'Discovery',
            'collection': 'Data Collection',
            'exfiltration': 'Data Exfiltration',
            'execution': 'Code Execution',
            'network': 'Network Activity',
            'registry': 'Registry Modification',
            'file': 'File Operation',
            'process': 'Process Creation',
            'service': 'Service Creation',
            'scheduled': 'Scheduled Task',
            'startup': 'Startup Modification'
        }
        
        # First, try to extract from metadata description
        if 'description' in metadata:
            desc_lower = metadata['description'].lower()
            for key, human_name in pattern_mappings.items():
                if key in desc_lower:
                    return human_name
        
        # Then try to match from rule name
        for key, human_name in pattern_mappings.items():
            if key in rule_lower:
                return human_name
        
        # If no specific match found, try to extract meaningful parts
        if '.' in rule_name:
            # Split by dots and look for meaningful parts
            parts = rule_name.split('.')
            for part in parts:
                part_lower = part.lower()
                for key, human_name in pattern_mappings.items():
                    if key in part_lower:
                        return human_name
        
        # If still no match, return a generic but readable description
        if any(word in rule_lower for word in ['win', 'msil', 'gen', 'generic']):
            return 'Windows Malware'
        elif any(word in rule_lower for word in ['unix', 'linux', 'elf']):
            return 'Linux Malware'
        elif any(word in rule_lower for word in ['android', 'apk', 'dex']):
            return 'Android Malware'
        elif any(word in rule_lower for word in ['mac', 'osx', 'apple']):
            return 'Mac Malware'
        elif any(word in rule_lower for word in ['office', 'doc', 'pdf']):
            return 'Document Malware'
        elif any(word in rule_lower for word in ['script', 'js', 'vbs', 'ps1']):
            return 'Script Malware'
        else:
            return 'Malware'

    def _get_match_description(self, match) -> str:
        """Get human-readable description of YARA match."""
        metadata = self._get_rule_metadata(match)
        human_readable = self._convert_yara_rule_to_human_readable(match.rule, metadata)
        return human_readable

    async def scan(self, file_path: Path) -> ScanResult:
        """
        Scan a file using YARA rules.
        
        Args:
            file_path: Path to the file to scan
            
        Returns:
            ScanResult: The scan results
        """
        if not self.initialized:
            await self.initialize()

        try:
            # Check memory pressure
            if warning := await memory_manager.check_memory_pressure():
                return ScanResult(
                    safe=True,
                    threats=[],
                    scan_time=datetime.now(timezone.utc),
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine=self.name,
                    confidence=0.0,
                    error=f"Memory pressure: {warning}"
                )

            threats: List[str] = []
            confidence = 0.6  # Base confidence

            # Use memory mapping for efficient file access
            with open(file_path, 'rb') as f:
                try:
                    # Try memory mapping first
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                        matches = self.rules.match(data=mm)
                except ValueError:
                    # Fallback for small files that can't be memory mapped
                    matches = self.rules.match(data=f.read())

            # Process matches
            if matches:
                for match in matches:
                    threat_desc = self._get_match_description(match)
                    threats.append(threat_desc)
                    
                    # Adjust confidence based on metadata
                    metadata = self._get_rule_metadata(match)
                    if metadata.get('confidence'):
                        try:
                            rule_confidence = float(metadata['confidence'])
                            confidence = max(confidence, rule_confidence)
                        except (ValueError, TypeError):
                            pass

            return ScanResult(
                safe=len(threats) == 0,
                threats=threats,
                scan_time=datetime.now(timezone.utc),
                file_size=file_path.stat().st_size,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=confidence if threats else 0.6
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
                error=str(e)
            )

    async def cleanup(self) -> None:
        """Cleanup YARA resources."""
        self.rules = None
        self._rules_cache.clear()
        self.initialized = False 