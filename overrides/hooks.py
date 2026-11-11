"""Documentation pages that are a file from the repository root.

``docs/guide.md`` is just ``{{ include README.md }}``: the README stays the one
copy of the documentation. Links those files make to each other are written for
the repository, so they are pointed at the matching pages of the site.
"""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
INCLUDE = re.compile(r"^\{\{ include (?P<file>[\w.-]+) \}\}\s*$")
PAGES = {
    "docs/benchmarks.md": "benchmarks.md",
    "SECURITY.md": "security.md",
    "CHANGELOG.md": "changelog.md",
    "README.md": "guide.md",
}
LINK = re.compile(r"\]\((?P<path>[^)#\s]+)(?P<anchor>#[^)\s]*)?\)")


def _site_link(match: re.Match[str]) -> str:
    path = match["path"]
    if path in PAGES:
        return f"]({PAGES[path]}{match['anchor'] or ''})"
    if path.startswith(("deploy/", "src/", "tests/", "bench/", "infra/", "control-plane/")):
        return "](#)"  # a file in the repository: no public page to link to
    return match[0]


def on_page_markdown(markdown: str, **_: object) -> str:
    include = INCLUDE.match(markdown.strip())
    if not include:
        return markdown
    return LINK.sub(_site_link, (ROOT / include["file"]).read_text(encoding="utf-8"))
