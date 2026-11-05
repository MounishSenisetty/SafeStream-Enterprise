"""Release artefacts must agree with the package version."""

import re
from pathlib import Path

from safestream_enterprise import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_manifest_deploys_the_current_version() -> None:
    # The manifest configures features of this version (e.g. the field-rules
    # ConfigMap); pinning an older image would silently ignore them.
    manifest = (ROOT / "deploy/kubernetes/kafka-redactor.yaml").read_text(encoding="utf-8")
    tags = re.findall(r"image: ghcr\.io/[\w.-]+/safestream-enterprise:(\S+)", manifest)
    assert tags == [__version__], f"manifest image tags {tags} != package version {__version__}"
