"""The packaged version (pyproject.toml) and the in-code VERSION constant must
agree. They are set in two places (SemVer for consumers vs. `brig --version`);
this guards against bumping one and forgetting the other.
"""

import re
from pathlib import Path

from brig.config import VERSION


def test_pyproject_version_matches_config():
    pyproject = (Path(__file__).parent.parent / "pyproject.toml").read_text()
    m = re.search(r'^version = "([^"]+)"', pyproject, re.MULTILINE)
    assert m, "could not find `version = \"...\"` in pyproject.toml"
    assert m.group(1) == VERSION, (
        f"version drift: pyproject.toml={m.group(1)} != brig.config.VERSION={VERSION}"
    )
