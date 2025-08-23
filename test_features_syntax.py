#!/usr/bin/env python3
"""
Test script to verify that features.py has no syntax errors
"""

import sys
import os

# Add the app directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'app'))

try:
    # Test importing the features module
    from scanner.features import PEFeatureExtractor
    print("✅ Successfully imported PEFeatureExtractor")
    
    # Test creating an instance
    extractor = PEFeatureExtractor()
    print("✅ Successfully created PEFeatureExtractor instance")
    
    print("\n🎉 All syntax checks passed! The features.py file is now valid.")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
