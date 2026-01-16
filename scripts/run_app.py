#!/usr/bin/env python3
"""
Startup script for IoT Anomaly Detection System
"""

import os
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

def main():
    """Main entry point for the application"""
    try:
        from main import main as app_main
        return app_main()
    except ImportError as e:
        print(f"Error importing main module: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())