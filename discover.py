#!/usr/bin/env python3
"""
EDOT Cloud Forwarder - AWS Log Source Discovery Tool

Entry point script for running without installation.
For installed usage, run: edot-discover
"""

import sys
from pathlib import Path

# Add src to path for direct execution without installation
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))

from edot_discovery.cli import main

if __name__ == "__main__":
    main()
