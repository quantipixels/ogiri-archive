"""AC3 must use the real JavaScript library, including its registration/session API."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from support import Settings


@pytest.mark.ac3
def test_AC3_real_dta_javascript_client(settings: Settings) -> None:
    script = Path(__file__).with_name("client.mjs")
    node = shutil.which("node")
    assert node is not None, "AC3 requires Node"
    result = subprocess.run(  # noqa: S603 -- fixed Node executable, trusted local script
        [node, str(script), settings.base_url, settings.mailpit_url, settings.profile],
        capture_output=True,
        text=True,
        timeout=45,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["client"] == "vanilla-token-auth@1.0.6"
    assert evidence["revoked"] is True
    assert evidence["trace"] == [
        {"method": "POST", "path": "/auth", "status": 200},
        {"method": "POST", "path": "/auth/sign_in", "status": 200},
        {"method": "GET", "path": "/auth/validate_token", "status": 200},
        {"method": "DELETE", "path": "/auth/sign_out", "status": 200},
    ]
