"""Current source release contract; historical reports are immutable."""
from pathlib import Path
import tomllib
import sys
if not __debug__ or sys.flags.optimize:
    raise RuntimeError("Release verification requires Python assertions; unset PYTHONOPTIMIZE and do not use -O")
ROOT=Path(__file__).resolve().parent.parent
CURRENT_VERSION=tomllib.loads((ROOT/'Cargo.toml').read_text(encoding='utf-8'))['workspace']['package']['version']
MCP_TOOLS=68
