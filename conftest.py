"""
conftest.py — pytest configuration for AI-RIDS
Adds the repository root to sys.path so all src.* imports resolve correctly.
"""
import sys
from pathlib import Path

# Ensure 'src' is importable as a package
sys.path.insert(0, str(Path(__file__).resolve().parent))
