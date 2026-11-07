import os
import sys
from pathlib import Path

# Make the project root importable when pytest is run from any directory.
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Keep tests away from the real runtime files.
os.environ.setdefault("PHISHING_TEST_MODE", "1")
