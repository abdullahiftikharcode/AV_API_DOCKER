from pathlib import Path
from typing import List
from pydantic_settings import BaseSettings
import os

class Settings(BaseSettings):
    # Server Configuration
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    MAX_FILE_SIZE_MB: int = 1536  # Increased to 1.5GB for large file testing
    SCAN_TIMEOUT_SECONDS: int = 300  # Increased timeout for large files
    TEMP_DIR: str = "/tmp/virus-scanner"
    LOG_LEVEL: str = "INFO"

    # Memory Management
    MAX_CONCURRENT_SCANS: int = 6
    MEMORY_LIMIT_MB: int = 2000  # Reduced per container for concurrent operation
    ENABLE_RESULT_CACHING: bool = True
    CACHE_TTL_HOURS: int = 24

    # ClamAV Configuration
    CLAMAV_HOST: str = "127.0.0.1"
    CLAMAV_PORT: int = 3310
    CLAMAV_MAX_FILESIZE: str = "1536M"  # Increased to 1.5GB
    CLAMAV_MAX_SCANSIZE: str = "1536M"  # Increased to 1.5GB
    CLAMAV_MAX_THREADS: int = 1  # Reduced for single-core containers
    CLAMAV_HEURISTIC_SCAN: bool = True

    # ML Detection Configuration
    ML_MODEL_PATH: str = str(Path(__file__).parent.parent / "data" / "ml_models")
    ML_ENABLE_PE_ANALYSIS: bool = True  # Enable LightGBM models for PE analysis
    ML_ENABLE_ENTROPY_ANALYSIS: bool = True
    ML_MODEL_CACHE_SIZE_MB: int = 512

    # YARA Configuration
    YARA_RULES_PATH: str = str(Path(__file__).parent.parent / "rules")
    YARA_MAX_RULES_MEMORY_MB: int = 1024
    YARA_ENABLE_FAST_MODE: bool = True

    # File Extensions Allowlist
    ALLOWED_EXTENSIONS: List[str] = [
        # Executables and System Files
        ".exe", ".dll", ".sys", ".drv", ".cpl", ".scr", ".msi", ".msix", ".msixbundle", ".msp", ".mst",
        ".com", ".bat", ".cmd", ".pif", ".reg", ".rgs", ".vbs", ".vbe", ".js", ".jse", ".ws", ".wsf", ".wsc", ".wsh",
        ".ps1", ".ps1xml", ".ps2", ".ps2xml", ".psc1", ".psc2", ".psd1", ".psm1", ".py", ".pyc", ".pyo",
        ".jar", ".class", ".apk", ".app", ".appx", ".appxbundle", ".ipa", ".deb", ".rpm", ".pkg", ".dmg",
        ".elf", ".out", ".bin", ".so", ".ko", ".o", ".a", ".lib", ".dylib", ".bundle",
        
        # Scripts and Interpreted Files
        ".sh", ".bash", ".csh", ".tcsh", ".ksh", ".zsh", ".pl", ".pm", ".rb", ".php", ".php3", ".asp", ".aspx",
        ".jsp", ".jsx", ".html", ".htm", ".xhtml", ".xml", ".xslt", ".css", ".scss", ".sass",
        ".awk", ".sed", ".perl", ".tcl", ".lua", ".r", ".m", ".scala", ".go", ".rs", ".swift",
        
        # Documents and Office Files
        ".doc", ".docx", ".docm", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".pptm",
        ".pdf", ".rtf", ".txt", ".csv", ".log", ".ini", ".cfg", ".conf", ".config",
        
        # Archives and Compressed Files
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".iso", ".udf",
        ".tgz", ".tbz2", ".txz", ".lzma", ".lz", ".lzo", ".lz4", ".zst",
        
        # Media and Binary Files
        ".mp3", ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv", ".webm", ".m4v",
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".svg", ".ico", ".cur",
        ".wav", ".flac", ".aac", ".ogg", ".wma", ".m4a", ".opus",
        
        # Development and Source Files
        ".c", ".cpp", ".cc", ".cxx", ".h", ".hpp", ".hh", ".hxx", ".java", ".cs", ".vb",
        ".pas", ".pascal", ".f", ".f90", ".f95", ".f03", ".f08", ".for", ".ftn",
        ".asm", ".s", ".S", ".inc", ".def", ".rc", ".res", ".ico", ".cur", ".ani",
        
        # Network and Web Files
        ".url", ".lnk", ".webloc", ".website", ".htm", ".html", ".shtml", ".xhtml",
        ".cgi", ".pl", ".py", ".php", ".jsp", ".asp", ".aspx", ".ashx", ".asmx",
        
        # Database and Data Files
        ".db", ".sqlite", ".sql", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml",
        ".ini", ".cfg", ".conf", ".config", ".properties", ".env", ".bashrc", ".profile",
        
        # Other Supported Extensions
        ".chm", ".hlp", ".inf", ".ins", ".msi", ".msp", ".mst", ".ocx", ".tlb", ".olb",
        ".gadget", ".widget", ".workflow", ".applescript", ".scpt", ".scptd", ".osa",
        ".seed", ".spr", ".sct", ".vdl", ".vdo", ".vxd", ".sys", ".386", ".vxd",
        ".obs", ".nsh", ".mrc", ".mpx", ".mxe", ".mcr", ".mel", ".mll", ".ms", ".msc",
        ".pcd", ".paf", ".prc", ".prg", ".prn", ".pvd", ".pwc", ".qpx", ".rbx", ".rox",
        ".rpm", ".run", ".sbs", ".scar", ".scf", ".script", ".seed", ".shb", ".shd", ".shs",
        ".spr", ".sys", ".thm", ".tms", ".u3p", ".wcm", ".wpk", ".wst", ".xap", ".xqt",
        ".zlq", ".ac", ".acr", ".action", ".ade", ".adp", ".air", ".application", ".bas",
        ".cmp", ".dek", ".dld", ".ebm", ".emf", ".esh", ".ezs", ".fky", ".frs", ".fxp",
        ".gpe", ".gpu", ".grp", ".hms", ".hta", ".htx", ".icd", ".iim", ".inf1", ".inx",
        ".ipf", ".isp", ".isu", ".je", ".job", ".jtd", ".kix", ".mem", ".mpkg", ".mrc",
        ".obs", ".osax", ".osx", ".ovl", ".pas", ".pcd", ".pex", ".pif", ".plsc", ".pm",
        ".prc", ".prg", ".prn", ".pvd", ".pwc", ".py", ".pyc", ".pyo", ".qpx", ".rb",
        ".rbx", ".reg", ".rgs", ".rox", ".rpj", ".rpm", ".run", ".sbs", ".scar", ".scf",
        ".scpt", ".scptd", ".scr", ".script", ".sct", ".seed", ".sh", ".shb", ".shd", ".shs",
        ".spr", ".sys", ".tcsh", ".tgz", ".thm", ".tlb", ".tms", ".u3p", ".udf", ".url",
        ".vb", ".vba", ".vbe", ".vbs", ".vbscript", ".vdl", ".vdo", ".vxd", ".wcm",
        ".widget", ".wmf", ".workflow", ".wpk", ".ws", ".wsc", ".wsf", ".wsh", ".wst",
        ".xap", ".xhtml", ".xpi", ".xqt", ".zlq", ".zsh"
    ]

    # Threat Intelligence
    THREAT_INTEL_PATH: str = str(Path(__file__).parent.parent / "data" / "threat_intel")
    HASH_DB_PATH: str = str(Path(THREAT_INTEL_PATH) / "malware_hashes.db")
    IP_BLACKLIST_PATH: str = str(Path(THREAT_INTEL_PATH) / "ip_blacklist.txt")
    DOMAIN_BLACKLIST_PATH: str = str(Path(THREAT_INTEL_PATH) / "domain_blacklist.txt")
    
    # HMAC Authentication
    HMAC_SECRET_KEY: str = ""  # Must be set via environment variable in .env file
    HMAC_ENABLED: bool = True
    HMAC_TIMESTAMP_TOLERANCE_SECONDS: int = 300  # 5 minutes tolerance for timestamp

    # MalwareBazaar Configuration
    MALWAREBazaar_API_KEY: str = ""  # Primary API key from environment variable
    MALWAREBazaar_API_KEY_BACKUP: str = ""  # Backup API key from environment variable
    MALWAREBazaar_ENABLED: bool = True
    MALWAREBazaar_TIMEOUT: int = 10  # API timeout in seconds

    # Bytescale Configuration
    BYTESCALE_API_KEY: str = ""  # Must be set via environment variable in .env file
    BYTESCALE_ACCOUNT_ID: str = ""  # Must be set via environment variable in .env file
    BYTESCALE_ENABLED: bool = True
    BYTESCALE_MAX_FILE_SIZE_MB: int = 500  # Only scan files under 500MB
    BYTESCALE_TIMEOUT: int = 30  # API timeout in seconds

    class Config:
        # Environment variables are loaded from Docker env_file, not from .env file
        case_sensitive = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        
        # Validate that HMAC secret key is set when HMAC is enabled
        if self.HMAC_ENABLED and not self.HMAC_SECRET_KEY:
            raise ValueError(
                f"HMAC_SECRET_KEY must be set as an environment variable when HMAC_ENABLED is True. "
                f"Current value: {os.environ.get('HMAC_SECRET_KEY', 'NOT_SET')}. "
                f"Please ensure the .env file is properly configured and Docker Compose is loading it."
            )
        
        # Validate that Bytescale API key and account ID are set when Bytescale is enabled
        if self.BYTESCALE_ENABLED and not self.BYTESCALE_API_KEY:
            raise ValueError(
                f"BYTESCALE_API_KEY must be set as an environment variable when BYTESCALE_ENABLED is True. "
                f"Current value: {os.environ.get('BYTESCALE_API_KEY', 'NOT_SET')}. "
                f"Please ensure the .env file is properly configured and Docker Compose is loading it."
            )
        
        if self.BYTESCALE_ENABLED and not self.BYTESCALE_ACCOUNT_ID:
            raise ValueError(
                f"BYTESCALE_ACCOUNT_ID must be set as an environment variable when BYTESCALE_ENABLED is True. "
                f"Current value: {os.environ.get('BYTESCALE_ACCOUNT_ID', 'NOT_SET')}. "
                f"Please ensure the .env file is properly configured and Docker Compose is loading it."
            )

# Create settings instance
settings = Settings()

# Directories are created in the Dockerfile during build
# This avoids issues with read-only filesystems in containers 