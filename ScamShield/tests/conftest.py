import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))  # project root (scamshield package)
sys.path.insert(0, str(Path(__file__).resolve().parent))         # tests folder (cases_v1)
