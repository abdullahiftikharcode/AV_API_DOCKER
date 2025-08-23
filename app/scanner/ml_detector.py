import torch
import torch.nn as nn
import numpy as np
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple, Dict
import math
import re
import sys
import os
from cachetools import TTLCache, cached

from .base import BaseScanner, ScanResult
from ..config import settings
from ..utils.memory_manager import memory_manager

# Import the real EMBER feature extractor
from .features import PEFeatureExtractor


class PENetwork(nn.Module):
    """
    SOREL-20M PENetwork architecture for PE file analysis.
    Based on the SOREL-20M implementation with multiple prediction heads.
    """
    def __init__(self, use_malware=True, use_counts=True, use_tags=True, 
                 n_tags=11, feature_dimension=2381, layer_sizes=None):
        super(PENetwork, self).__init__()
        self.use_malware = use_malware
        self.use_counts = use_counts
        self.use_tags = use_tags
        self.n_tags = n_tags
        
        if layer_sizes is None:
            layer_sizes = [512, 512, 128]
            
        # Build the base network
        layers = []
        p = 0.05
        for i, ls in enumerate(layer_sizes):
            if i == 0:
                layers.append(nn.Linear(feature_dimension, ls))
            else:
                layers.append(nn.Linear(layer_sizes[i-1], ls))
            layers.append(nn.LayerNorm(ls))
            layers.append(nn.ELU())
            layers.append(nn.Dropout(p))
        
        self.model_base = nn.Sequential(*tuple(layers))
        
        # Prediction heads
        if self.use_malware:
            self.malware_head = nn.Sequential(
                nn.Linear(layer_sizes[-1], 1),
                nn.Sigmoid()
            )
        
        if self.use_counts:
            self.count_head = nn.Linear(layer_sizes[-1], 1)
            
        if self.use_tags:
            self.tag_head = nn.Sequential(
                nn.Linear(layer_sizes[-1], 64),
                nn.ELU(),
                nn.Linear(64, 64),
                nn.ELU(),
                nn.Linear(64, n_tags),
                nn.Sigmoid()
            )

    def forward(self, data):
        rv = {}
        base_result = self.model_base.forward(data)
        
        if self.use_malware:
            rv['malware'] = self.malware_head(base_result)
        if self.use_counts:
            rv['count'] = self.count_head(base_result)
        if self.use_tags:
            rv['tags'] = self.tag_head(base_result)
            
        return rv


class MLDetector(BaseScanner):
    """Machine Learning-based malware detection using SOREL-20M models with real EMBER v2 features.
    
    SOREL-20M only supports specific PE file extensions:
    .exe, .dll, .sys, .ocx, .scr, .cpl, .drv, .efi, .mui, .acm, .ax, .fon, .tsp, .mun
    
    Files with other extensions will be analyzed using entropy-based fallback detection.
    """

    def __init__(self):
        super().__init__("ML Detector")
        self.version = "4.0"
        self.description = "SOREL-20M ML-based detection with EMBER v2 features"
        
        # Initialize models
        self.models = {}
        self.device = torch.device('cpu')
        
        # Initialize EMBER v2 feature extractor (exactly as used in SOREL-20M training)
        self.feature_extractor = PEFeatureExtractor(feature_version=2)
        
        # SOREL-20M behavioral tags
        self.behavioral_tags = [
            "adware", "flooder", "ransomware", "dropper", "spyware", "packed",
            "crypto_miner", "file_infector", "installer", "worm", "downloader"
        ]
        
        print("INFO: MLDetector initialized with SOREL-20M architecture and EMBER v2 features")
        
        # Define SOREL-20M supported extensions
        self.sorel_supported_extensions = {
            '.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv', 
            '.efi', '.mui', '.acm', '.ax', '.fon', '.tsp', '.mun'
        }
        
        print(f"INFO: SOREL-20M supports {len(self.sorel_supported_extensions)} file extensions: {sorted(self.sorel_supported_extensions)}")

    async def initialize(self) -> None:
        """Initialize the ML detector by loading SOREL-20M models."""
        try:
            models_dir = Path("/app/data/ml_models")
            
            if not models_dir.exists():
                print(f"WARNING: ML models directory not found: {models_dir}")
                self.initialized = True
                return
            
            # Look specifically for ffnn_seed0.pt first, then fall back to any .pt file
            target_model = models_dir / "ffnn_seed0.pt"
            if target_model.exists():
                model_path = target_model
                print(f"Found target model: {model_path}")
            else:
                # Fall back to first available model
                model_files = list(models_dir.glob("*.pt"))
                
                if not model_files:
                    print("WARNING: No .pt model files found in ML models directory")
                    self.initialized = True
                    return
                
                print(f"Target model ffnn_seed0.pt not found. Found {len(model_files)} other model files: {[f.name for f in model_files]}")
                model_path = model_files[0]
                print(f"Loading fallback model: {model_path}")
            
            print(f"Loading model: {model_path}")
            
            # Initialize the model architecture
            model = PENetwork(
                use_malware=True,
                use_counts=True,
                use_tags=True,
                n_tags=len(self.behavioral_tags),
                feature_dimension=2381,  # EMBER v2 feature dimension
                layer_sizes=[512, 512, 128]
            )
            
            # Load the trained weights
            checkpoint = torch.load(model_path, map_location=self.device)
            
            # Handle different checkpoint formats
            if 'model_state_dict' in checkpoint:
                model.load_state_dict(checkpoint['model_state_dict'])
            elif 'state_dict' in checkpoint:
                model.load_state_dict(checkpoint['state_dict'])
            else:
                model.load_state_dict(checkpoint)
            
            model.eval()
            model.to(self.device)
            
            self.models['primary'] = model
            print(f"Successfully loaded model: {model_path}")
            
            # Verify feature dimension matches
            expected_dim = self.feature_extractor.dim
            print(f"EMBER v2 feature dimension: {expected_dim}")
            if expected_dim != 2381:
                print(f"WARNING: Expected 2381 features, got {expected_dim}")
            
            print(f"✅ MLDetector initialized with SINGLE model: {model_path.name}")
            print(f"✅ This will significantly speed up scanning compared to using 5 models")
            
            self.initialized = True
            
        except Exception as e:
            print(f"ERROR: Failed to initialize ML detector: {e}")
            # Fall back to entropy-based detection
        self.initialized = True

    def _should_skip_ml_analysis(self, file_path: Path) -> bool:
        """Check if file type should skip ML analysis."""
        file_extension = file_path.suffix.lower()
        
        # SOREL-20M only supports specific PE file extensions
        # These are the only extensions that should be processed by SOREL-20M
        allowed_sorel_extensions = {
            '.exe', '.dll', '.sys', '.ocx', '.scr', '.cpl', '.drv', 
            '.efi', '.mui', '.acm', '.ax', '.fon', '.tsp', '.mun'
        }
        
        # Skip files that are not in the SOREL-20M allowed list
        return file_extension not in self.sorel_supported_extensions
    
    def is_sorel_supported_extension(self, file_extension: str) -> bool:
        """Check if a file extension is supported by SOREL-20M."""
        return file_extension.lower() in self.sorel_supported_extensions

    async def _analyze_file_ml(self, file_path: Path) -> Tuple[bool, float, List[str]]:
        """Analyze file using SOREL-20M ML models with real EMBER v2 features."""
        try:
            if 'primary' not in self.models:
                print("WARNING: No ML models loaded, falling back to entropy analysis")
                return await self._analyze_file_entropy(file_path)
            
            # Read file bytes for EMBER feature extraction
            with open(file_path, 'rb') as f:
                file_bytes = f.read()
            
            if len(file_bytes) < 64:  # Too small to be a valid PE
                print("WARNING: File too small for PE analysis, using entropy fallback")
                return await self._analyze_file_entropy(file_path)
            
            # Extract EMBER v2 features using the real extractor
            print(f"DEBUG: Extracting EMBER v2 features from {file_path.name}")
            try:
                features = self.feature_extractor.feature_vector(file_bytes)
                print(f"DEBUG: EMBER v2 features extracted successfully, dimension: {len(features)}")
            except Exception as e:
                print(f"ERROR: EMBER feature extraction failed: {e}")
                print("Falling back to entropy analysis")
                return await self._analyze_file_entropy(file_path)
            
            # Verify feature dimension
            if len(features) != 2381:
                print(f"WARNING: Expected 2381 features, got {len(features)}")
                if len(features) < 2381:
                    # Pad with zeros if too short
                    features = np.pad(features, (0, 2381 - len(features)), 'constant')
                else:
                    # Truncate if too long
                    features = features[:2381]
            
            # Convert to tensor
            features_tensor = torch.tensor(features, dtype=torch.float32).unsqueeze(0)
            features_tensor = features_tensor.to(self.device)
            
            # Run inference with single model
            print(f"DEBUG: Running inference with single ML model (ffnn_seed0.pt)")
            with torch.no_grad():
                predictions = self.models['primary'](features_tensor)
            
            # Extract results
            malware_prob = predictions['malware'].item()
            count_pred = predictions['count'].item() if 'count' in predictions else 0.0
            tag_probs = predictions['tags'].squeeze().cpu().numpy() if 'tags' in predictions else np.zeros(len(self.behavioral_tags))
            
            print(f"DEBUG: ML predictions - malware: {malware_prob:.3f}, count: {count_pred:.3f}")
            
            # Determine threat status
            is_threat = malware_prob > 0.5
            confidence = malware_prob if is_threat else (1.0 - malware_prob)
            
            # Generate threats list
            threats = []
            if is_threat:
                threats.append(f"ML Detection: Malware probability {malware_prob:.1%}")
                
                # Add behavioral tags
                for i, (tag, prob) in enumerate(zip(self.behavioral_tags, tag_probs)):
                    if prob > 0.3:  # Threshold for tag detection
                        threats.append(f"Behavior: {tag} (confidence: {prob:.1%})")
            
            return is_threat, confidence, threats
            
        except Exception as e:
            print(f"ERROR: ML analysis failed: {e}")
            # Fall back to entropy analysis
            return await self._analyze_file_entropy(file_path)

    async def _analyze_file_entropy(self, file_path: Path) -> Tuple[bool, float, List[str]]:
        """Fallback entropy-based analysis."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if len(data) == 0:
                return False, 0.0, []
            
            # Calculate file entropy
            entropy = self._calculate_entropy(data)
            print(f"DEBUG: Entropy analysis - entropy: {entropy:.3f}")
            
            # Simple heuristic: very high entropy might indicate packed/encrypted content
            if entropy > 7.5:
                confidence = min(0.8, (entropy - 7.0) / 1.0)
                threats = [f"High entropy content ({entropy:.2f}) - possibly packed/encrypted"]
                return True, confidence, threats
            
            return False, 0.0, []
            
        except Exception as e:
            print(f"Error in entropy analysis: {e}")
            return False, 0.0, []

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy of data."""
        if len(data) == 0:
            return 0.0
            
        # Count frequency of each byte
        frequency = {}
        for byte in data:
            frequency[byte] = frequency.get(byte, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        for count in frequency.values():
            p = float(count) / data_len
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy

    async def scan(self, file_path: Path) -> ScanResult:
        """Scan file using SOREL-20M ML models with real EMBER v2 features."""
        start_time = datetime.now()
        
        try:
            print(f"DEBUG: ML detector analyzing {file_path}")
            
            # Check memory pressure
            if warning := await memory_manager.check_memory_pressure():
                return ScanResult(
                    safe=True,
                    threats=[],
                    scan_time=datetime.utcnow(),
                    file_size=file_path.stat().st_size,
                    file_name=file_path.name,
                    scan_engine=self.name,
                    confidence=0.0,
                    error=f"Memory pressure: {warning}"
                )
            
            # Choose analysis method
            if self._should_skip_ml_analysis(file_path):
                print(f"DEBUG: Skipping SOREL-20M ML analysis for {file_path.name} (extension {file_path.suffix.lower()} not supported)")
                is_threat, confidence, threats = await self._analyze_file_entropy(file_path)
            else:
                # Use SOREL-20M ML analysis with real EMBER features
                print(f"DEBUG: Using SOREL-20M ML analysis for {file_path.name} (supported extension: {file_path.suffix.lower()})")
                is_threat, confidence, threats = await self._analyze_file_ml(file_path)
            
            scan_time = datetime.now()
            duration_ms = int((scan_time - start_time).total_seconds() * 1000)
            
            print(f"DEBUG: ML detector result - threat: {is_threat}, confidence: {confidence:.3f}")

            return ScanResult(
                safe=not is_threat,
                threats=threats,
                scan_time=scan_time,
                file_size=file_path.stat().st_size if file_path.exists() else 0,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=confidence
            )

        except Exception as e:
            scan_time = datetime.now()
            duration_ms = int((scan_time - start_time).total_seconds() * 1000)
            
            print(f"ERROR: ML detector failed: {e}")
            
            return ScanResult(
                safe=True,
                threats=[],
                scan_time=scan_time,
                file_size=file_path.stat().st_size if file_path.exists() else 0,
                file_name=file_path.name,
                scan_engine=self.name,
                confidence=0.0,
                error=str(e)
            )

    async def cleanup(self) -> None:
        """Cleanup ML resources."""
        # Clear models from memory
        for model_name, model in self.models.items():
            del model
        self.models.clear()
        
        # Clear CUDA cache if available
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        
        self.initialized = False 
        print("DEBUG: ML detector cleanup completed")