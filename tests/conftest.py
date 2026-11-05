"""Make src/ importable and expose paths to the sample artifacts."""
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

SAMPLE_APP = ROOT / "sample-app"
SAMPLE_APP_PATCHED = ROOT / "sample-app-patched"
CVE_FEED = ROOT / "data" / "cve_feed.json"


@pytest.fixture
def sample_app() -> Path:
    return SAMPLE_APP


@pytest.fixture
def sample_app_patched() -> Path:
    return SAMPLE_APP_PATCHED


@pytest.fixture
def feed() -> Path:
    return CVE_FEED
