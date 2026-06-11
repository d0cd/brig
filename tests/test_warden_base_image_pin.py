"""The base mitmproxy image is pinned in two places that must stay in lockstep:
`warden.proxy.BASE_IMAGE` (the single source of truth, imported by the proxy and
by `brig image warmup`) and the warden image Dockerfile (which can't import
Python). This guards against a partial bump that would build the warden image
from one base while warmup/fallback reference another.
"""

import re
from pathlib import Path

from warden.proxy import BASE_IMAGE


def _dockerfile() -> str:
    return (
        Path(__file__).parent.parent / "src" / "warden" / "image" / "Dockerfile"
    ).read_text()


def test_dockerfile_from_matches_base_image():
    m = re.search(r"^FROM\s+(\S+)", _dockerfile(), re.MULTILINE)
    assert m, "no FROM line in warden Dockerfile"
    assert m.group(1) == BASE_IMAGE, (
        f"base image drift: Dockerfile FROM={m.group(1)} != BASE_IMAGE={BASE_IMAGE}"
    )


def test_base_digest_appears_in_dockerfile():
    # The LABEL records the digest without the registry prefix; a digest bump to
    # BASE_IMAGE must update the Dockerfile too.
    digest = BASE_IMAGE.split("@", 1)[1]
    assert digest in _dockerfile(), f"BASE_IMAGE digest {digest} not found in Dockerfile"
