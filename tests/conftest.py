import sys
from pathlib import Path

# Make cloudlink-core importable from test files
CORE = Path(__file__).resolve().parent.parent
if str(CORE) not in sys.path:
    sys.path.insert(0, str(CORE))
