"""``matrix_ingress``: the caller's network is the credential (#330).

The token that rode in every request URL is gone; the address the request
came from picks the profile. These are the config rules that make that safe:
one agent per network, and an old ``token_env`` refused with its replacement
named rather than silently ignored.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from pydantic import ValidationError

from mcp_trentina_crunchtools.gateway.errors import ProfileConfigError
from mcp_trentina_crunchtools.gateway.loader import load_profiles
from mcp_trentina_crunchtools.gateway.profile import MatrixIngressConfig

if TYPE_CHECKING:
    from pathlib import Path


def _write(tmp_path: Path, *networks: str) -> Path:
    body = "profiles:\n"
    for n, net in enumerate(networks):
        body += (
            f"  agent{n}:\n"
            "    auth:\n      bearer_token_env: TEST_TOKEN\n"
            f"    matrix_ingress:\n      source_networks: ['{net}']\n"
        )
    path = tmp_path / "profiles.yaml"
    path.write_text(body, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _token(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TEST_TOKEN", "t")


def test_separate_networks_load(tmp_path: Path) -> None:
    cfg = load_profiles(_write(tmp_path, "10.89.1.0/24", "10.89.2.0/24", "fd00:1::/64"))
    ingress = cfg.profiles["agent0"].matrix_ingress
    assert ingress is not None
    assert [str(n) for n in ingress.source_networks] == ["10.89.1.0/24"]


@pytest.mark.parametrize(
    ("a", "b"), [("10.89.1.0/24", "10.89.1.128/25"), ("10.0.0.0/8", "10.89.2.0/24")]
)
def test_overlapping_networks_are_refused(tmp_path: Path, a: str, b: str) -> None:
    with pytest.raises(ProfileConfigError, match="overlap"):
        load_profiles(_write(tmp_path, a, b))


def test_token_env_is_refused_with_what_replaced_it() -> None:
    with pytest.raises(ValidationError, match="source_networks") as err:
        MatrixIngressConfig.model_validate({"token_env": "MATRIX_TOKEN"})
    assert "since 0.51.0" in str(err.value)


@pytest.mark.parametrize("networks", [[], ["10.89.1.5/24"], ["trentina"]])
def test_a_network_must_be_a_network(networks: list[str]) -> None:
    """None, a host address with a prefix (a typo for the subnet), or a name."""
    with pytest.raises(ValidationError):
        MatrixIngressConfig.model_validate({"source_networks": networks})
