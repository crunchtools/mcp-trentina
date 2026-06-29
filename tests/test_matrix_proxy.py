"""Tests for gateway/matrix_proxy.py — path traversal and route registration."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from mcp_trentina_crunchtools.gateway.matrix_proxy import register_matrix_routes
from mcp_trentina_crunchtools.gateway.proxy_utils import sanitize_proxy_path


class TestRegisterMatrixRoutes:
    """Validation in register_matrix_routes."""

    def test_rejects_http_upstream(self) -> None:
        with pytest.raises(ValueError, match="https://"):
            register_matrix_routes(MagicMock(), upstream="http://insecure.example.com")

    def test_accepts_https_upstream(self) -> None:
        mock_server = MagicMock()
        register_matrix_routes(mock_server, upstream="https://matrix.org")
        mock_server.custom_route.assert_called_once()


class TestMatrixPathTraversal:
    """Path traversal is rejected via the shared sanitize_proxy_path."""

    def test_clean_matrix_path(self) -> None:
        assert sanitize_proxy_path("_matrix/client/v3/sync") == (
            "_matrix/client/v3/sync"
        )

    def test_traversal_in_matrix_path(self) -> None:
        assert sanitize_proxy_path("_matrix/../../../etc/passwd") is None
